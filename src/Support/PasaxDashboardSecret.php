<?php

namespace Pasax\SecureMonitor\Support;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Pasax\SecureMonitor\Models\PasaxSetting;
use RuntimeException;

/**
 * Pengelola rahasia URL dashboard acak (`PASAX_DASHBOARD_SECRET`) dan
 * kredensial login dashboard (`PASAX_DASHBOARD_USERNAME` & `PASAX_DASHBOARD_PASSWORD`),
 * serta identitas pemilik akun Pasax terverifikasi untuk akses tanpa password yang aman.
 *
 * Rahasia ini dibuat sekali saat instalasi (atau lewat `pasax:secret`) dan
 * dipakai sebagai kunci HMAC untuk menandatangani token dashboard aktif pada
 * sesi sekaligus sebagai secret key untuk hashing password dashboard yang
 * disimpan ke database.
 */
class PasaxDashboardSecret
{
    public const ENV_KEY = "PASAX_DASHBOARD_SECRET";

    public const USERNAME_ENV_KEY = "PASAX_DASHBOARD_USERNAME";

    public const PASSWORD_ENV_KEY = "PASAX_DASHBOARD_PASSWORD";

    public const OWNER_EMAIL_ENV_KEY = "PASAX_OWNER_EMAIL";

    public const OWNER_USERNAME_ENV_KEY = "PASAX_OWNER_USERNAME";

    public const PASSWORDLESS_OWNER_ENV_KEY = "PASAX_DASHBOARD_PASSWORDLESS_OWNER";

    public const DEFAULT_USERNAME = "admin";

    public const DEFAULT_PASSWORD = "Admin";

    public const DB_PASSWORD_HASH_KEY = "dashboard_password_hash";

    public const DB_USERNAME_KEY = "dashboard_username";

    public const DB_OWNER_EMAIL_KEY = "pasax_owner_email";

    public const DB_OWNER_USERNAME_KEY = "pasax_owner_username";

    public const DB_OWNER_NAME_KEY = "pasax_owner_name";

    public const DB_OWNER_PLAN_KEY = "pasax_owner_plan";

    public const LENGTH = 48;

    /**
     * Buat nilai rahasia baru yang aman secara kriptografis.
     */
    public static function generate(): string
    {
        return Str::random(self::LENGTH);
    }

    /**
     * Baca nilai rahasia dari berkas env tanpa mengubahnya.
     */
    public static function readFromEnvFile(string $path): ?string
    {
        return self::readEnvKeyFromFile($path, self::ENV_KEY);
    }

    /**
     * Baca nilai username dari berkas env tanpa mengubahnya.
     */
    public static function readUsernameFromEnvFile(string $path): ?string
    {
        return self::readEnvKeyFromFile($path, self::USERNAME_ENV_KEY);
    }

    /**
     * Baca nilai default password dari berkas env tanpa mengubahnya.
     */
    public static function readPasswordFromEnvFile(string $path): ?string
    {
        return self::readEnvKeyFromFile($path, self::PASSWORD_ENV_KEY);
    }

    /**
     * Baca email pemilik akun Pasax dari berkas .env tanpa mengubahnya.
     */
    public static function readOwnerEmailFromEnvFile(string $path): ?string
    {
        return self::readEnvKeyFromFile($path, self::OWNER_EMAIL_ENV_KEY);
    }

    /**
     * Baca username pemilik akun Pasax dari berkas .env tanpa mengubahnya.
     */
    public static function readOwnerUsernameFromEnvFile(string $path): ?string
    {
        return self::readEnvKeyFromFile($path, self::OWNER_USERNAME_ENV_KEY);
    }

    /**
     * Baca kunci tertentu dari berkas env tanpa mengubah isinya.
     */
    public static function readEnvKeyFromFile(
        string $path,
        string $key,
    ): ?string {
        if (!File::exists($path)) {
            return null;
        }

        $content = File::get($path);
        $pattern = "/^" . preg_quote($key, "/") . '=(.*)$/m';

        if (preg_match($pattern, $content, $matches) !== 1) {
            return null;
        }

        $value = self::normalize((string) ($matches[1] ?? ""));

        return $value === "" ? null : $value;
    }

    /**
     * Pastikan baris `PASAX_DASHBOARD_USERNAME` ada pada berkas env.
     */
    public static function ensureUsernameInEnvFile(
        string $path,
        string $default = self::DEFAULT_USERNAME,
    ): bool {
        if (!File::exists($path)) {
            return false;
        }

        $content = File::get($path);
        $pattern = "/^" . preg_quote(self::USERNAME_ENV_KEY, "/") . '=(.*)$/m';

        if (preg_match($pattern, $content) === 1) {
            return false;
        }

        $passwordPattern =
            "/^(" . preg_quote(self::PASSWORD_ENV_KEY, "/") . '=.*)$/m';
        $secretPattern = "/^(" . preg_quote(self::ENV_KEY, "/") . '=.*)$/m';

        if (preg_match($passwordPattern, $content) === 1) {
            $content = (string) preg_replace(
                $passwordPattern,
                self::USERNAME_ENV_KEY . "=" . $default . "\n$1",
                $content,
                1,
            );
        } elseif (preg_match($secretPattern, $content) === 1) {
            $content = (string) preg_replace(
                $secretPattern,
                self::USERNAME_ENV_KEY . "=" . $default . "\n$1",
                $content,
                1,
            );
        } else {
            $content =
                rtrim($content) .
                "\n" .
                self::USERNAME_ENV_KEY .
                "=" .
                $default .
                "\n";
        }

        File::put($path, $content);

        return true;
    }

    /**
     * Pastikan baris `PASAX_DASHBOARD_PASSWORD` ada pada berkas env.
     */
    public static function ensurePasswordInEnvFile(
        string $path,
        string $default = self::DEFAULT_PASSWORD,
    ): bool {
        if (!File::exists($path)) {
            return false;
        }

        $content = File::get($path);
        $pattern = "/^" . preg_quote(self::PASSWORD_ENV_KEY, "/") . '=(.*)$/m';

        if (preg_match($pattern, $content) === 1) {
            return false;
        }

        $secretPattern = "/^(" . preg_quote(self::ENV_KEY, "/") . '=.*)$/m';
        if (preg_match($secretPattern, $content) === 1) {
            $content = (string) preg_replace(
                $secretPattern,
                self::PASSWORD_ENV_KEY . "=" . $default . "\n$1",
                $content,
                1,
            );
        } else {
            $content =
                rtrim($content) .
                "\n" .
                self::PASSWORD_ENV_KEY .
                "=" .
                $default .
                "\n";
        }

        File::put($path, $content);

        return true;
    }

    /**
     * Pastikan baris `PASAX_DASHBOARD_SECRET` ada pada berkas env.
     *
     * - `$generate = true`: isi kosong / baris hilang / `--force` dibuatkan
     *   nilai baru.
     * - `$generate = false`: hanya memastikan baris ada, dibiarkan kosong
     *   (dipakai untuk `.env.example` agar rahasia tidak ikut ter-commit).
     *
     * @return array{exists: bool, changed: bool, generated: bool, secret: ?string}
     */
    public static function ensureInEnvFile(
        string $path,
        bool $force = false,
        bool $generate = true,
    ): array {
        $result = [
            "exists" => File::exists($path),
            "changed" => false,
            "generated" => false,
            "secret" => null,
        ];

        if (!$result["exists"]) {
            return $result;
        }

        // Pastikan juga baris PASAX_DASHBOARD_USERNAME & PASAX_DASHBOARD_PASSWORD ada
        self::ensureUsernameInEnvFile($path);
        self::ensurePasswordInEnvFile($path);

        $content = File::get($path);
        $pattern = "/^" . preg_quote(self::ENV_KEY, "/") . '=(.*)$/m';
        $hasLine = preg_match($pattern, $content, $matches) === 1;
        $current = $hasLine
            ? self::normalize((string) ($matches[1] ?? ""))
            : null;
        if ($current === "") {
            $current = null;
        }
        $result["secret"] = $current;

        $needsValue = $force || !$hasLine || $current === null;

        if ($generate && $needsValue) {
            $secret = self::generate();

            if ($hasLine) {
                $content = (string) preg_replace(
                    $pattern,
                    self::ENV_KEY . "=" . $secret,
                    $content,
                    1,
                );
            } else {
                $content =
                    rtrim($content) .
                    "\n" .
                    self::ENV_KEY .
                    "=" .
                    $secret .
                    "\n";
            }

            File::put($path, $content);

            $result["changed"] = true;
            $result["generated"] = true;
            $result["secret"] = $secret;

            return $result;
        }

        if (!$hasLine) {
            $content = rtrim($content) . "\n" . self::ENV_KEY . "=" . "\n";
            File::put($path, $content);
            $result["changed"] = true;

            return $result;
        }

        if (!$generate) {
            // Contoh konfigurasi tidak boleh menyimpan rahasia nyata, termasuk
            // nilai warisan instalasi lama yang mungkin sudah ter-commit.
            $content = (string) preg_replace(
                $pattern,
                self::ENV_KEY . "=",
                $content,
                1,
            );

            if ($content !== File::get($path)) {
                File::put($path, $content);
                $result["changed"] = true;
            }

            $result["secret"] = null;

            return $result;
        }

        return $result;
    }

    /**
     * Turunkan username pemilik dari respons verifikasi akun Pasax Cloud.
     *
     * @param  array<string, mixed>  $user
     */
    public static function deriveUsernameFromUserData(array $user): string
    {
        $rawUsername = trim(
            (string) ($user["username"] ?? ($user["handle"] ?? "")),
        );
        if ($rawUsername !== "") {
            $clean = strtolower(
                (string) preg_replace("/[^a-zA-Z0-9._-]/", "", $rawUsername),
            );
            if ($clean !== "") {
                return $clean;
            }
        }

        $email = trim((string) ($user["email"] ?? ""));
        if ($email !== "" && str_contains($email, "@")) {
            $local = strtolower(Str::before($email, "@"));
            $clean = (string) preg_replace("/[^a-z0-9._-]/", "", $local);
            if ($clean !== "") {
                return $clean;
            }
        }

        $name = trim((string) ($user["name"] ?? ""));
        if ($name !== "") {
            $slug = Str::slug($name, ".");
            if ($slug !== "") {
                return $slug;
            }
        }

        return "";
    }

    /**
     * Simpan metadata identitas pemilik akun Pasax ke database (`pasax_settings`).
     *
     * @param  array<string, mixed>  $user
     * @return array{email: ?string, username: ?string, name: ?string, plan: ?string}
     */
    public static function storeOwnerIdentityInDatabase(array $user): array
    {
        $email = strtolower(trim((string) ($user["email"] ?? "")));
        $username = self::deriveUsernameFromUserData($user);
        $name = trim((string) ($user["name"] ?? ""));
        $plan = strtoupper(trim((string) ($user["plan"] ?? "")));

        $pairs = [
            self::DB_OWNER_EMAIL_KEY => $email !== "" ? $email : null,
            self::DB_OWNER_USERNAME_KEY => $username !== "" ? $username : null,
            self::DB_OWNER_NAME_KEY => $name !== "" ? $name : null,
            self::DB_OWNER_PLAN_KEY => $plan !== "" ? $plan : null,
        ];

        try {
            if (
                PasaxDatabase::schema()->hasTable(
                    new PasaxSetting()->getTable(),
                )
            ) {
                foreach ($pairs as $key => $value) {
                    if ($value !== null) {
                        PasaxSetting::query()->updateOrCreate(
                            ["key" => $key],
                            ["value" => $value],
                        );
                    }
                }
            }
        } catch (\Throwable) {
            // Abaikan jika tabel belum siap
        }

        return [
            "email" => $pairs[self::DB_OWNER_EMAIL_KEY],
            "username" => $pairs[self::DB_OWNER_USERNAME_KEY],
            "name" => $pairs[self::DB_OWNER_NAME_KEY],
            "plan" => $pairs[self::DB_OWNER_PLAN_KEY],
        ];
    }

    /**
     * Resolusi identitas pemilik akun Pasax dari config, database, atau berkas .env.
     *
     * @return array{email: ?string, username: ?string, name: ?string, plan: ?string, configured: bool}
     */
    public static function resolveOwnerIdentity(): array
    {
        $email = "";
        $username = "";
        $name = "";
        $plan = "";

        try {
            $email = trim(
                (string) config("pasax.dashboard.auth.owner_email", ""),
            );
            $username = trim(
                (string) config("pasax.dashboard.auth.owner_username", ""),
            );
        } catch (\Throwable) {
        }

        try {
            if (
                PasaxDatabase::schema()->hasTable(
                    new PasaxSetting()->getTable(),
                )
            ) {
                $stored = PasaxSetting::query()
                    ->whereIn("key", [
                        self::DB_OWNER_EMAIL_KEY,
                        self::DB_OWNER_USERNAME_KEY,
                        self::DB_OWNER_NAME_KEY,
                        self::DB_OWNER_PLAN_KEY,
                    ])
                    ->pluck("value", "key");

                if (
                    $email === "" &&
                    !empty($stored[self::DB_OWNER_EMAIL_KEY])
                ) {
                    $email = trim((string) $stored[self::DB_OWNER_EMAIL_KEY]);
                }
                if (
                    $username === "" &&
                    !empty($stored[self::DB_OWNER_USERNAME_KEY])
                ) {
                    $username = trim(
                        (string) $stored[self::DB_OWNER_USERNAME_KEY],
                    );
                }
                if (!empty($stored[self::DB_OWNER_NAME_KEY])) {
                    $name = trim((string) $stored[self::DB_OWNER_NAME_KEY]);
                }
                if (!empty($stored[self::DB_OWNER_PLAN_KEY])) {
                    $plan = strtoupper(
                        trim((string) $stored[self::DB_OWNER_PLAN_KEY]),
                    );
                }
            }
        } catch (\Throwable) {
        }

        $envPath = base_path(".env");
        if ($email === "") {
            $email = (string) (self::readOwnerEmailFromEnvFile($envPath) ?? "");
        }
        if ($username === "") {
            $username =
                (string) (self::readOwnerUsernameFromEnvFile($envPath) ?? "");
        }

        if ($username === "" && $email !== "") {
            $username = self::deriveUsernameFromUserData(["email" => $email]);
        }

        $emailVal = $email !== "" ? strtolower($email) : null;
        $usernameVal = $username !== "" ? strtolower($username) : null;

        return [
            "email" => $emailVal,
            "username" => $usernameVal,
            "name" => $name !== "" ? $name : null,
            "plan" => $plan !== "" ? $plan : null,
            "configured" => $emailVal !== null || $usernameVal !== null,
        ];
    }

    /**
     * Periksa apakah mode akses pemilik terikat akun (passwordless) aktif dan terkonfigurasi.
     */
    public static function isPasswordlessOwnerEnabled(): bool
    {
        try {
            $enabled = (bool) config(
                "pasax.dashboard.auth.passwordless_owner",
                true,
            );
        } catch (\Throwable) {
            $enabled = true;
        }

        if (!$enabled) {
            return false;
        }

        return self::resolveOwnerIdentity()["configured"];
    }

    /**
     * Cocokkan user aplikasi host yang sedang terautentikasi terhadap identitas pemilik Pasax.
     *
     * Jika `owner_email` terkonfigurasi, hanya email yang identik (case-insensitive) yang diterima
     * (menghindari spoofing via kolom `name`/`username`). Jika hanya `owner_username` yang dikonfigurasi,
     * kolom `username` (non-kosong) milik user dicocokkan.
     */
    public static function matchesOwnerAccount(mixed $user): bool
    {
        if (!is_object($user) && !is_array($user)) {
            return false;
        }

        $identity = self::resolveOwnerIdentity();
        if (!$identity["configured"]) {
            return false;
        }

        $userEmail = is_array($user)
            ? $user["email"] ?? null
            : $user->email ?? null;
        $userUsername = is_array($user)
            ? $user["username"] ?? null
            : $user->username ?? null;

        $normalizedUserEmail = is_string($userEmail)
            ? strtolower(trim($userEmail))
            : "";
        $normalizedUserUsername = is_string($userUsername)
            ? strtolower(trim($userUsername))
            : "";

        if (!empty($identity["email"])) {
            if ($normalizedUserEmail !== "") {
                return hash_equals($identity["email"], $normalizedUserEmail);
            }

            if (
                !empty($identity["username"]) &&
                $normalizedUserUsername !== ""
            ) {
                return hash_equals(
                    $identity["username"],
                    $normalizedUserUsername,
                );
            }

            return false;
        }

        if (!empty($identity["username"]) && $normalizedUserUsername !== "") {
            return hash_equals($identity["username"], $normalizedUserUsername);
        }

        return false;
    }

    /**
     * Resolusi secret key untuk menandatangani token SSO pemilik (utamakan PASAX_LICENSE_KEY).
     */
    public static function resolveSsoSigningSecret(): string
    {
        try {
            $licenseKey = trim(
                (string) config(
                    "pasax.cloud.license_key",
                    config("pasax.cloud.key", ""),
                ),
            );
            if ($licenseKey !== "") {
                return $licenseKey;
            }
        } catch (\Throwable) {
        }

        $envPath = base_path(".env");
        foreach (
            ["PASAX_LICENSE_KEY", "PASAX_CLOUD_KEY", "PASAX_API_KEY"]
            as $envKey
        ) {
            $fromEnv = self::readEnvKeyFromFile($envPath, $envKey);
            if ($fromEnv !== null && $fromEnv !== "") {
                return $fromEnv;
            }
        }

        try {
            $dashSecret = trim((string) config("pasax.dashboard.secret", ""));
            if ($dashSecret !== "") {
                return $dashSecret;
            }
        } catch (\Throwable) {
        }

        return (string) (self::readFromEnvFile($envPath) ?? "");
    }

    /**
     * Hasilkan token SSO singkat ber-HMAC SHA-256 untuk akses dashboard pemilik terikat akun.
     */
    public static function generateOwnerSsoToken(
        string $subject,
        int $ttlSeconds = 300,
        ?string $secret = null,
    ): string {
        $signingKey = $secret ?? self::resolveSsoSigningSecret();
        $cleanSubject = strtolower(trim($subject));

        if ($signingKey === "" || $cleanSubject === "") {
            throw new RuntimeException(
                "Kunci penandatanganan atau subjek pemilik Pasax belum tersedia.",
            );
        }

        $now = time();
        $payload = [
            "sub" => $cleanSubject,
            "iat" => $now,
            "exp" => $now + max(10, $ttlSeconds),
            "nonce" => bin2hex(random_bytes(8)),
        ];

        $json = (string) json_encode($payload, JSON_UNESCAPED_SLASHES);
        $encodedPayload = self::base64UrlEncode($json);
        $signature = hash_hmac("sha256", $encodedPayload, $signingKey, true);

        return $encodedPayload . "." . self::base64UrlEncode($signature);
    }

    /**
     * Verifikasi token SSO pemilik akun Pasax.
     *
     * @return array{valid: bool, subject: ?string, reason: ?string}
     */
    public static function verifyOwnerSsoToken(
        string $token,
        ?string $secret = null,
    ): array {
        if (!self::isPasswordlessOwnerEnabled()) {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "passwordless_disabled",
            ];
        }

        $parts = explode(".", trim($token));
        if (count($parts) !== 2 || $parts[0] === "" || $parts[1] === "") {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "malformed",
            ];
        }

        [$encodedPayload, $encodedSignature] = $parts;
        $signingKey = $secret ?? self::resolveSsoSigningSecret();

        if ($signingKey === "") {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "missing_secret",
            ];
        }

        $expectedSig = self::base64UrlEncode(
            hash_hmac("sha256", $encodedPayload, $signingKey, true),
        );
        if (!hash_equals($expectedSig, $encodedSignature)) {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "invalid_signature",
            ];
        }

        $decoded = self::base64UrlDecode($encodedPayload);
        $payload = is_string($decoded) ? json_decode($decoded, true) : null;

        if (
            !is_array($payload) ||
            empty($payload["sub"]) ||
            empty($payload["exp"]) ||
            empty($payload["nonce"])
        ) {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "invalid_payload",
            ];
        }

        if ((int) $payload["exp"] < time()) {
            return ["valid" => false, "subject" => null, "reason" => "expired"];
        }

        $subject = strtolower(trim((string) $payload["sub"]));
        $identity = self::resolveOwnerIdentity();

        $matchesEmail =
            !empty($identity["email"]) &&
            hash_equals($identity["email"], $subject);
        $matchesUsername =
            !empty($identity["username"]) &&
            hash_equals($identity["username"], $subject);

        if (!$matchesEmail && !$matchesUsername) {
            return [
                "valid" => false,
                "subject" => null,
                "reason" => "subject_mismatch",
            ];
        }

        return [
            "valid" => true,
            "subject" => $subject,
            "reason" => null,
        ];
    }

    /**
     * Hash password dasbor menggunakan HMAC SHA-256 dengan secret key PASAX_DASHBOARD_SECRET.
     */
    public static function hashPassword(
        string $password,
        string $secret,
    ): string {
        return hash_hmac("sha256", $password, $secret);
    }

    /**
     * Dapatkan hash password yang tersimpan di database (tabel pasax_settings).
     */
    public static function getStoredPasswordHash(): ?string
    {
        try {
            return PasaxSetting::query()
                ->where("key", self::DB_PASSWORD_HASH_KEY)
                ->value("value");
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Simpan hash password baru ke database (tabel pasax_settings).
     */
    public static function storePasswordInDatabase(
        string $password,
        string $secret,
    ): void {
        $hash = self::hashPassword($password, $secret);

        PasaxSetting::query()->updateOrCreate(
            ["key" => self::DB_PASSWORD_HASH_KEY],
            ["value" => $hash],
        );
    }

    /**
     * Periksa apakah password sudah pernah diperbarui dan disimpan di database.
     */
    public static function isPasswordStoredInDatabase(): bool
    {
        $hash = self::getStoredPasswordHash();

        return !empty($hash);
    }

    /**
     * Verifikasi password input terhadap database, default bawaan, atau secret darurat.
     *
     * @return array{valid: bool, is_default: bool, is_emergency: bool}
     */
    public static function verifyPassword(
        string $inputPassword,
        string $secret,
        string $defaultPassword = self::DEFAULT_PASSWORD,
    ): array {
        $storedHash = self::getStoredPasswordHash();
        $isEmergencySecret =
            $secret !== "" && hash_equals($secret, $inputPassword);

        // 1. Jika password kustom sudah pernah disimpan di database
        if (!empty($storedHash)) {
            $calculated = self::hashPassword($inputPassword, $secret);
            $isCustomValid = hash_equals($storedHash, $calculated);
            $valid = $isCustomValid || $isEmergencySecret;

            return [
                "valid" => $valid,
                "is_default" => false,
                "is_emergency" => $isEmergencySecret && !$isCustomValid,
            ];
        }

        // 2. Jika belum disimpan di database, periksa terhadap default password atau secret
        $isDefault = hash_equals($defaultPassword, $inputPassword);
        $valid = $isDefault || $isEmergencySecret;

        return [
            "valid" => $valid,
            "is_default" => $isDefault,
            "is_emergency" => $isEmergencySecret && !$isDefault,
        ];
    }

    /**
     * Buat format tampilan untuk konsol (mis. baris penugasan env).
     */
    public static function formatEnvLine(string $secret): string
    {
        return self::ENV_KEY . "=" . $secret;
    }

    /**
     * Normalisasi nilai dari berkas .env: buang petik dan whitespace luar.
     */
    protected static function normalize(string $raw): string
    {
        $trimmed = trim($raw);

        // Jika dibungkus tanda kutip tunggal/ganda
        if (
            (str_starts_with($trimmed, '"') && str_ends_with($trimmed, '"')) ||
            (str_starts_with($trimmed, "'") && str_ends_with($trimmed, "'"))
        ) {
            return trim(substr($trimmed, 1, -1));
        }

        // Potong komentar inline (# ...) jika ada
        if (str_contains($trimmed, "#")) {
            $parts = explode("#", $trimmed, 2);
            $trimmed = trim($parts[0]);
        }

        return $trimmed;
    }

    protected static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), "+/", "-_"), "=");
    }

    protected static function base64UrlDecode(string $data): ?string
    {
        $padded = strtr($data, "-_", "+/");
        $remainder = strlen($padded) % 4;
        if ($remainder > 0) {
            $padded .= str_repeat("=", 4 - $remainder);
        }

        $decoded = base64_decode($padded, true);

        return is_string($decoded) ? $decoded : null;
    }
}
