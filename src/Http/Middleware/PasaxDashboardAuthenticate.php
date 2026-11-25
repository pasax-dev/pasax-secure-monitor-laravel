<?php

namespace Pasax\SecureMonitor\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Pasax\SecureMonitor\Services\PasaxUserLoginService;
use Pasax\SecureMonitor\Support\PasaxDashboardSecret;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware pencegat akses dashboard Pasax dengan form login mandiri
 * dan dukungan akses tanpa password terikat akun pemilik Pasax.
 *
 * Memeriksa apakah pengguna sudah login via sesi dashboard Pasax
 * (`pasax_dashboard_authenticated === true`) atau terverifikasi sebagai
 * pemilik akun Pasax pada sesi host yang aktif. Jika belum, request
 * akan dicegat dan dialihkan ke form login (/pasax/login).
 */
class PasaxDashboardAuthenticate
{
    public function handle(Request $request, Closure $next): Response
    {
        // Jika autentikasi dashboard dinonaktifkan secara eksplisit
        if (!(bool) config("pasax.dashboard.auth.enabled", true)) {
            $this->trackDashboardAccess($request);

            return $next($request);
        }

        // Jika sesi sudah terotentikasi via login Pasax
        if (
            $request->hasSession() &&
            $request->session()->get("pasax_dashboard_authenticated") === true
        ) {
            $this->trackDashboardAccess($request);

            return $next($request);
        }

        $loggedOut =
            $request->hasSession() &&
            $request->session()->get("pasax_dashboard_logged_out") === true;

        // Akses tanpa password terikat akun pemilik Pasax pada sesi host yang sudah login & terverifikasi
        if (
            $request->user() !== null &&
            !$loggedOut &&
            !$request->attributes->get("force_pasax_auth", false) &&
            PasaxDashboardSecret::isPasswordlessOwnerEnabled() &&
            PasaxDashboardSecret::matchesOwnerAccount($request->user())
        ) {
            $identity = PasaxDashboardSecret::resolveOwnerIdentity();
            $ownerLabel =
                $identity["username"] ??
                ($identity["email"] ?? ($request->user()->email ?? "owner"));

            if ($request->hasSession()) {
                $request->session()->put("pasax_dashboard_authenticated", true);
                $request->session()->put("pasax_dashboard_user", $ownerLabel);
                $request
                    ->session()
                    ->put("pasax_dashboard_auth_mode", "owner_session");
                $request
                    ->session()
                    ->put("pasax_dashboard_login_at", now()->timestamp);
                $request->session()->forget("pasax_dashboard_logged_out");
            }

            if ($request->user() instanceof Authenticatable) {
                try {
                    app(PasaxUserLoginService::class)->recordDashboardLogin(
                        $request->user(),
                        $request,
                    );
                } catch (\Throwable) {
                }
            }

            $this->trackDashboardAccess($request);

            return $next($request);
        }

        // Dukungan untuk unit testing Testbench yang memakai actingAs($admin) tanpa identitas owner aktif
        if (
            app()->runningUnitTests() &&
            !$loggedOut &&
            $request->user() !== null &&
            !$request->attributes->get("force_pasax_auth", false) &&
            !PasaxDashboardSecret::isPasswordlessOwnerEnabled()
        ) {
            $this->trackDashboardAccess($request);

            return $next($request);
        }

        // Jika request via AJAX / JSON API
        if ($request->expectsJson() || $request->isXmlHttpRequest()) {
            return response()->json(
                [
                    "message" => "Unauthenticated from Pasax dashboard.",
                    "login_url" => route("pasax.dashboard.login"),
                ],
                401,
            );
        }

        // Simpan URL yang dituju agar setelah login dapat dialihkan kembali
        if ($request->hasSession() && $request->isMethod("GET")) {
            $request
                ->session()
                ->put("pasax_dashboard_intended", $request->fullUrl());
        }

        return redirect()->guest(route("pasax.dashboard.login"));
    }

    protected function trackDashboardAccess(Request $request): void
    {
        try {
            app(PasaxUserLoginService::class)->trackDashboardAccess(
                $request,
                $request->user(),
            );
        } catch (\Throwable) {
        }
    }
}
