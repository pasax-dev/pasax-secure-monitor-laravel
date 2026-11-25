<?php

namespace Pasax\SecureMonitor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Pasax\SecureMonitor\Models\PasaxLog;
use Pasax\SecureMonitor\Services\PasaxCloudService;
use Pasax\SecureMonitor\Services\PasaxService;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Inspects every incoming request for attack payloads (SQL injection, XSS,
 * path traversal, ...), stores the findings and blocks repeat offenders.
 */
class PasaxDetectSecurityThreats
{
    public function __construct(
        protected PasaxService $service,
        protected ?PasaxCloudService $cloudService = null,
    ) {
        $this->cloudService =
            $cloudService ??
            (app()->bound(PasaxCloudService::class)
                ? app(PasaxCloudService::class)
                : null);
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->service->enabled()) {
            return $next($request);
        }

        try {
            $threats = $this->service->inspect($request);
        } catch (Throwable) {
            $threats = [];
        }

        if ($threats === []) {
            return $next($request);
        }

        $ip = $this->service->resolveClientIp($request);
        $deviceId = $this->service->resolveDeviceId($request);
        $localIp = $this->service->resolveLocalIp($request);

        // An authenticated administrator is never blocked or rejected.
        // Threats are logged for audit purposes with 'admin_bypass'.
        if ($this->service->isAdminRequest($request)) {
            $this->service->record($request, $threats, 'admin_bypass');

            return $next($request);
        }

        // Mode Pasif Grace: Jika API Key tidak ada atau masa percobaan 14 hari telah habis,
        // semua aksi pemblokiran dinonaktifkan (tidak ada penolakan, tidak ada blokir IP).
        // Sistem hanya mencatat counter serangan yang diobservasi secara pasif.
        if (
            $this->cloudService !== null &&
            ! $this->cloudService->isProtectionActive()
        ) {
            $this->service->record($request, $threats, 'unprotected_passive');

            $firstThreat = $threats[0] ?? [];
            $this->cloudService->reportThreat([
                'event_type' => 'UNPROTECTED_OBSERVED_ATTACK',
                'ip_address' => $ip,
                'threat_level' => $firstThreat['level'] ?? 'medium',
                'blocked' => false,
                'path' => $request->path(),
                'method' => $request->method(),
                'rule_label' => $firstThreat['label'] ?? null,
                'evidence' => $firstThreat['evidence'] ?? null,
                'user_agent' => $request->userAgent(),
            ]);

            return $next($request);
        }

        $log = $this->service->record($request, $threats);

        // A whitelisted IP/device is only logged for the record, never blocked.
        if ($this->service->isWhitelisted($ip, $deviceId, $localIp)) {
            return $next($request);
        }

        // Zero tolerance signatures (webshell upload, null byte, path
        // traversal, .htaccess/.env probing, SSTI, scanners, injected PHP)
        // block the client on the very first hit.
        if ($this->service->shouldInstantBlock($threats)) {
            $block = $this->service->blockImmediately(
                $ip,
                $threats,
                $deviceId,
                $localIp,
            );

            $this->markLogAsBlocked($log, 'instant_block');

            return PasaxBlockIpAddress::blockedResponse(
                $request,
                $block?->reason,
            );
        }

        $block = $this->service->autoBlockIfNeeded($ip, $deviceId, $localIp);

        if ($block !== null) {
            $this->markLogAsBlocked($log);

            return PasaxBlockIpAddress::blockedResponse(
                $request,
                $block->reason,
            );
        }

        if ($this->shouldReject($threats)) {
            $this->markLogAsBlocked($log, 'rejected');

            return PasaxBlockIpAddress::forbiddenResponse(
                $request,
                'Permintaan ditolak karena mengandung payload yang tidak diizinkan.',
                'Payload berbahaya terdeteksi.',
            );
        }

        return $next($request);
    }

    /**
     * Reject the request outright when it carries a critical payload and the
     * "block_suspicious_requests" option is enabled.
     *
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string}>  $threats
     */
    protected function shouldReject(array $threats): bool
    {
        if (! config('pasax.block_suspicious_requests', false)) {
            return false;
        }

        foreach ($threats as $threat) {
            if (($threat['level'] ?? 'low') === 'critical') {
                return true;
            }
        }

        return false;
    }

    protected function markLogAsBlocked(
        ?PasaxLog $log,
        string $action = 'auto_blocked',
    ): void {
        if ($log === null) {
            return;
        }

        try {
            $log->forceFill([
                'was_blocked' => true,
                'action_taken' => $action,
            ])->save();
        } catch (Throwable) {
            // Ignore: the audit entry is already stored.
        }
    }
}
