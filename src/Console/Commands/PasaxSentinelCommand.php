<?php

namespace Pasax\SecureMonitor\Console\Commands;

use Illuminate\Console\Command;
use Pasax\SecureMonitor\Services\PasaxSentinelBridge;

class PasaxSentinelCommand extends Command
{
    protected $signature = 'pasax:sentinel
                            {--block= : IP address to drop instantly via Linux kernel firewall}
                            {--unblock= : IP address to remove from Linux firewall drop list}
                            {--reason=ANOMALOUS_PAYLOAD_DETECTED : Justification tag for block action}
                            {--duration=1440 : Duration of ban in minutes}
                            {--ping : Test health and roundtrip latency with daemon}
                            {--status : Inspect sentinel status and kernel ruleset metrics}';

    protected $description = 'Communicate directly with the local Pasax Sentinel host daemon over Unix socket';

    public function handle(PasaxSentinelBridge $bridge): int
    {
        $this->info('[Pasax Sentinel IPC Diagnostics]');
        $this->line("Socket target: {$bridge->getSocketPath()}");

        // 1. Block IP Option
        if ($ip = $this->option('block')) {
            $reason = (string) $this->option('reason');
            $duration = (int) $this->option('duration');

            $this->comment(
                "Requesting kernel firewall drop for IP: {$ip} (Reason: {$reason})...",
            );
            $success = $bridge->blockIP($ip, $reason, $duration);

            if ($success) {
                $this->info(
                    "✔ Successfully instructed Sentinel to block {$ip} at the kernel level.",
                );

                return self::SUCCESS;
            }

            $this->error(
                "✖ Failed to block {$ip}. Check if sentinel daemon is running with CAP_NET_ADMIN.",
            );

            return self::FAILURE;
        }

        // 2. Unblock IP Option
        if ($ip = $this->option('unblock')) {
            $this->comment("Requesting unban for IP: {$ip}...");
            $success = $bridge->unblockIP($ip);

            if ($success) {
                $this->info(
                    "✔ Successfully instructed Sentinel to unblock {$ip}.",
                );

                return self::SUCCESS;
            }

            $this->error("✖ Failed to unblock {$ip}. Check daemon logs.");

            return self::FAILURE;
        }

        // 3. Ping Option
        if ($this->option('ping')) {
            $this->comment('Pinging Sentinel daemon...');
            $pong = $bridge->ping();

            if ($pong) {
                $this->info(
                    '✔ PONG received from Sentinel daemon. IPC socket is fully operational.',
                );

                return self::SUCCESS;
            }

            $this->error('✖ PING failed: Sentinel daemon did not respond.');

            return self::FAILURE;
        }

        // Default or --status
        $this->info('Inspecting Sentinel daemon status...');
        $status = $bridge->status();

        if ($status !== null) {
            $this->info('✔ Sentinel Daemon is ONLINE');

            $blockedSample = array_map(function ($item) {
                if (is_array($item)) {
                    return $item['ip'] ?? json_encode($item);
                }

                return (string) $item;
            }, (array) ($status['blocked_ips'] ?? []));

            $this->table(
                ['Metric', 'Value'],
                [
                    [
                        'Firewall Driver',
                        $status['firewall_driver'] ?? 'unknown',
                    ],
                    ['Kernel Drops Count', $status['blocked_count'] ?? 0],
                    ['Active Drops Sample', implode(', ', $blockedSample)],
                ],
            );

            return self::SUCCESS;
        }

        $this->warn('⚠ Sentinel daemon is OFFLINE or socket is not created.');
        $this->line(
            'Ensure `pasax-sentinel` daemon is running on the host system.',
        );

        return self::FAILURE;
    }
}
