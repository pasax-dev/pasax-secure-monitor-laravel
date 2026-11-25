<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Pasax\SecureMonitor\Models\PasaxBlockedIp;
use Pasax\SecureMonitor\Models\PasaxLog;
use Pasax\SecureMonitor\Services\PasaxServerSecurityService;
use Pasax\SecureMonitor\Support\PasaxDashboardSecret;
use Pasax\SecureMonitor\Support\PasaxDatabase;
use Pasax\SecureMonitor\Support\PasaxTableResolver;

uses(RefreshDatabase::class);

$scenarioTempDir = "";
$originalOwnerEmail = null;
$originalOwnerUsername = null;
$originalLicenseKey = null;

beforeEach(function () use (
    &$scenarioTempDir,
    &$originalOwnerEmail,
    &$originalOwnerUsername,
    &$originalLicenseKey,
) {
    $scenarioTempDir = sys_get_temp_dir() . "/pasax_yes_scenario_" . uniqid();
    File::makeDirectory($scenarioTempDir, 0755, true, true);

    $originalOwnerEmail = config("pasax.dashboard.auth.owner_email");
    $originalOwnerUsername = config("pasax.dashboard.auth.owner_username");
    $originalLicenseKey = config("pasax.cloud.license_key");

    DB::purge("pasax_sqlite");
    DB::purge("legacy_host_sqlite");
    PasaxTableResolver::clearCache();

    config()->set("pasax.database.connection", "pasax_sqlite");
    config()->set(
        "pasax.database.path",
        $scenarioTempDir . "/pasax/pasax.sqlite",
    );
    config()->set(
        "pasax.database.backup_path",
        $scenarioTempDir . "/pasax/backups",
    );
    config()->set("pasax.database.sqlite_wal", true);
    config()->set("pasax.dashboard.enabled", true);
    config()->set("pasax.dashboard.auth.enabled", true);
    config()->set("pasax.dashboard.rotating", true);
    config()->set(
        "pasax.dashboard.secret",
        "WT3J5pZLlQJkVPueACpFbxzBH0g1mSoB0Gcn7yKhKVp9WTvi",
    );

    $iso = PasaxDatabase::ensureIsolatedSchemaReady(false);
    expect($iso["migrated"])->toBeTrue();
});

afterEach(function () use (
    &$scenarioTempDir,
    &$originalOwnerEmail,
    &$originalOwnerUsername,
    &$originalLicenseKey,
) {
    DB::purge("pasax_sqlite");
    DB::purge("legacy_host_sqlite");
    PasaxTableResolver::clearCache();

    config()->set("database.default", "sqlite");
    config()->set("pasax.database.connection", "pasax_sqlite");
    config()->set(
        "pasax.database.path",
        storage_path("app/pasax/pasax.sqlite"),
    );
    config()->set(
        "pasax.database.backup_path",
        storage_path("app/pasax/backups"),
    );
    config()->set("pasax.dashboard.auth.owner_email", $originalOwnerEmail);
    config()->set(
        "pasax.dashboard.auth.owner_username",
        $originalOwnerUsername,
    );
    config()->set("pasax.cloud.license_key", $originalLicenseKey);
    config()->set("pasax.cloud.key", $originalLicenseKey);

    if ($scenarioTempDir !== "" && File::isDirectory($scenarioTempDir)) {
        File::deleteDirectory($scenarioTempDir);
    }
});

test(
    "scenario A: isolated sqlite storage lives outside public_path, enforces WAL, and WAF blocks direct sqlite web probes",
    function () {
        $status = PasaxDatabase::sqliteStatus();

        expect($status["connection"])
            ->toBe("pasax_sqlite")
            ->and($status["driver"])
            ->toBe("sqlite")
            ->and($status["is_isolated"])
            ->toBeTrue()
            ->and($status["wal_enabled"])
            ->toBeTrue()
            ->and($status["exists"])
            ->toBeTrue()
            ->and(str_starts_with($status["path"], public_path()))
            ->toBeFalse();

        $gitignore = File::get(dirname($status["path"]) . "/.gitignore");
        expect($gitignore)
            ->toContain("*.sqlite*")
            ->toContain("*.db*")
            ->toContain("backups/");

        // Server security audit reports healthy isolated SQLite & WAL checks
        $audit = app(PasaxServerSecurityService::class);
        $audit->forget();
        $scan = $audit->scan(true);
        $checks = collect($scan["categories"] ?? [])
            ->flatMap(fn(array $cat): array => $cat["checks"] ?? [])
            ->keyBy("id");

        expect($checks->has("pasax_database"))
            ->toBeTrue()
            ->and($checks->get("pasax_database")["status"])
            ->toBe("ok")
            ->and($checks->has("pasax_sqlite_wal"))
            ->toBeTrue()
            ->and($checks->get("pasax_sqlite_wal")["status"])
            ->toBe("ok");

        // Direct HTTP probes trying to download SQLite database/backup files are blocked immediately
        config()->set("pasax.instant_block.enabled", true);

        foreach (
            [
                "203.0.113.10" => "/storage/app/pasax/pasax.sqlite",
                "203.0.113.11" => "/pasax-admin-2026-11-25.sqlite",
                "203.0.113.12" => "/pasax.sqlite-wal",
                "203.0.113.13" => "/database.sqlite",
            ]
            as $attackerIp => $probePath
        ) {
            $this->withServerVariables(["REMOTE_ADDR" => $attackerIp])
                ->withHeaders(["User-Agent" => "SqliteProbeBot/" . $attackerIp])
                ->get($probePath)
                ->assertStatus(403);

            expect(
                PasaxBlockedIp::where("ip_address", $attackerIp)
                    ->where("is_active", true)
                    ->exists(),
            )->toBeTrue();
        }
    },
);

test(
    "scenario B: real attack payloads write only to isolated pasax_sqlite and cross-db User relation works",
    function () {
        config()->set("pasax.instant_block.enabled", true);
        config()->set("pasax.block_enforcement", true);

        $owner = User::factory()->create([
            "name" => "Real Host Admin",
            "email" => "real-host-admin@example.test",
        ]);

        // First attack: SSTI probe from attacker IP
        $this->withServerVariables(["REMOTE_ADDR" => "198.51.100.44"])
            ->get("/?payload={{7*7}}")
            ->assertStatus(403);

        // Subsequent clean request from same IP stays blocked at perimeter
        $this->withServerVariables(["REMOTE_ADDR" => "198.51.100.44"])
            ->get("/")
            ->assertStatus(403);

        expect(
            DB::connection("pasax_sqlite")
                ->table("pasax_logs")
                ->where("ip_address", "198.51.100.44")
                ->exists(),
        )
            ->toBeTrue()
            ->and(
                DB::connection("pasax_sqlite")
                    ->table("pasax_blocked_ips")
                    ->where("ip_address", "198.51.100.44")
                    ->exists(),
            )
            ->toBeTrue()
            // Host :memory: database stays clean of attacker logs from isolated run
            ->and(
                DB::connection("sqlite")
                    ->table("pasax_logs")
                    ->where("ip_address", "198.51.100.44")
                    ->exists(),
            )
            ->toBeFalse();

        // Cross-DB relation between pasax_sqlite PasaxLog and host sqlite User
        $log = PasaxLog::create([
            "user_id" => $owner->id,
            "ip_address" => "198.51.100.45",
            "event_type" => "sqli",
            "threat_level" => "critical",
            "path" => "/login",
            "evidence" => "Cross-DB test",
        ]);

        $loaded = PasaxLog::with("user")->find($log->id);
        expect($loaded?->user)
            ->not->toBeNull()
            ->and($loaded->user->email)
            ->toBe("real-host-admin@example.test");
    },
);

test(
    "scenario C: atomic VACUUM INTO backup via CLI and authenticated dashboard download rejects guests & path traversal",
    function () {
        config()->set("pasax.dashboard.auth.owner_email", "roby@pasax.web.id");
        config()->set("pasax.dashboard.auth.owner_username", "robykartis");
        config()->set("pasax.dashboard.auth.passwordless_owner", true);

        PasaxLog::create([
            "ip_address" => "203.0.113.90",
            "event_type" => "xss",
            "threat_level" => "high",
            "path" => "/comment",
            "evidence" => "Backup integrity test row",
        ]);

        // CLI backup
        $this->artisan("pasax:backup")
            ->expectsOutputToContain(
                "Backup snapshot SQLite Pasax berhasil dibuat!",
            )
            ->assertSuccessful();

        $backups = PasaxDatabase::listBackups();
        expect($backups)
            ->toHaveCount(1)
            ->and($backups[0]["filename"])
            ->toStartWith("pasax-robykartis-");

        $pdo = new PDO("sqlite:" . $backups[0]["path"]);
        expect(
            (int) $pdo
                ->query(
                    "SELECT COUNT(*) FROM pasax_logs WHERE ip_address = '203.0.113.90'",
                )
                ->fetchColumn(),
        )->toBe(1);

        // Guest cannot create or download backups
        $this->postJson("/pasax-guestToken12345/server/backup")->assertStatus(
            401,
        );
        $this->getJson("/pasax/server/backup/download")->assertStatus(401);
        $this->get("/pasax/server/backup/download")->assertRedirect(
            route("pasax.dashboard.login"),
        );

        // Authenticated owner via rotating dashboard can create & download snapshot
        $owner = User::factory()->create([
            "name" => "Roby Kartis",
            "email" => "roby@pasax.web.id",
        ]);

        $entry = $this->actingAs($owner)->get("/pasax");
        $entry->assertRedirect();
        $slugPath = trim(
            (string) parse_url(
                (string) $entry->headers->get("Location"),
                PHP_URL_PATH,
            ),
            "/",
        );

        $createResp = $this->actingAs($owner)
            ->postJson("/" . $slugPath . "/server/backup")
            ->assertOk()
            ->assertJsonPath("success", true);

        $createdFilename = (string) $createResp->json("data.filename");

        $downloadResp = $this->actingAs($owner)->get(
            "/" .
                $slugPath .
                "/server/backup/download?file=" .
                urlencode($createdFilename),
        );

        $downloadResp
            ->assertOk()
            ->assertHeader("content-type", "application/x-sqlite3")
            ->assertHeader("x-content-type-options", "nosniff");

        $slugPath =
            (string) ($downloadResp->headers->get("X-Pasax-Dashboard-Slug") ?:
            $slugPath);

        // Path traversal attempts rejected with 403
        foreach (
            [
                "../../etc/passwd",
                "../pasax.sqlite",
                "subdir/pasax.sqlite",
                "/etc/passwd",
                "shell.php",
            ]
            as $maliciousFile
        ) {
            $this->actingAs($owner)
                ->followingRedirects()
                ->get(
                    "/" .
                        $slugPath .
                        "/server/backup/download?file=" .
                        urlencode($maliciousFile),
                )
                ->assertStatus(403);
        }
    },
);

test(
    "scenario D: account-bound passwordless owner login, logout lock, spoofing block, and HMAC SSO token verification",
    function () {
        config()->set("pasax.dashboard.auth.owner_email", "owner@pasax.web.id");
        config()->set("pasax.dashboard.auth.owner_username", "owneracct");
        config()->set("pasax.dashboard.auth.passwordless_owner", true);
        config()->set(
            "pasax.cloud.license_key",
            "psk_live_pasax_yes_sso_secret_2026",
        );
        config()->set("pasax.cloud.key", "psk_live_pasax_yes_sso_secret_2026");

        $owner = User::factory()->create([
            "name" => "Pasax Owner",
            "email" => "owner@pasax.web.id",
        ]);

        // 1. Authenticated host owner enters rotating dashboard passwordlessly
        $res = $this->actingAs($owner)->followingRedirects()->get("/pasax");
        $res->assertOk()->assertSee("sec-sidebar-version");
        expect(session("pasax_dashboard_authenticated"))
            ->toBeTrue()
            ->and(session("pasax_dashboard_auth_mode"))
            ->toBe("owner_session")
            ->and(session("pasax_dashboard_user"))
            ->toBe("owneracct");

        // Server audit page also renders isolated SQLite status & owner info
        $this->actingAs($owner)
            ->followingRedirects()
            ->get("/pasax/server")
            ->assertOk()
            ->assertSee("pasax_sqlite")
            ->assertSee("owneracct");

        // 2. Explicit logout prevents immediate re-entry until one-click confirm
        $this->actingAs($owner)
            ->post(route("pasax.dashboard.logout"))
            ->assertRedirect(route("pasax.dashboard.login"));
        expect(session("pasax_dashboard_logged_out"))
            ->toBeTrue()
            ->and(session("pasax_dashboard_authenticated"))
            ->toBeNull();

        $this->actingAs($owner)
            ->withSession(["pasax_dashboard_logged_out" => true])
            ->get("/pasax")
            ->assertRedirect(route("pasax.dashboard.login"));

        $this->actingAs($owner)
            ->withSession(["pasax_dashboard_logged_out" => true])
            ->post(route("pasax.dashboard.login.owner"))
            ->assertRedirect();
        expect(session("pasax_dashboard_authenticated"))->toBeTrue();

        // 3. Account spoofing / non-owner user MUST be rejected even with same display name
        $spoofer = User::factory()->create([
            "name" => "owneracct",
            "email" => "spoofer@attacker.test",
        ]);

        $this->flushSession();
        $this->actingAs($spoofer)
            ->get("/pasax")
            ->assertRedirect(route("pasax.dashboard.login"));
        $this->actingAs($spoofer)
            ->postJson(route("pasax.dashboard.login.owner"))
            ->assertStatus(403);

        // 4. Form login without password is rejected
        $this->post(route("pasax.dashboard.login.submit"), [
            "username" => "owneracct",
        ])->assertSessionHasErrors("password");

        // 5. Valid HMAC SSO token authenticates; tampered token rejected
        $this->flushSession();
        $validSso = PasaxDashboardSecret::generateOwnerSsoToken(
            "owner@pasax.web.id",
            300,
        );
        $this->get(
            route("pasax.dashboard.login", ["sso_token" => $validSso]),
        )->assertRedirect("/pasax");
        expect(session("pasax_dashboard_auth_mode"))->toBe("owner_sso");

        $this->flushSession();
        $this->get(
            route("pasax.dashboard.login", [
                "sso_token" => $validSso . "tampered",
            ]),
        )
            ->assertOk()
            ->assertSee("tidak valid atau telah kedaluwarsa");
        expect(session("pasax_dashboard_authenticated"))->toBeNull();
    },
);

test(
    "scenario E: upgrade from pre-sqlite host DB migrates schema and preserves all existing host pasax rows",
    function () use (&$scenarioTempDir) {
        $legacyHostDb = $scenarioTempDir . "/legacy_host.sqlite";
        $newIsolatedDb = $scenarioTempDir . "/migrated_pasax/pasax.sqlite";

        File::put($legacyHostDb, "");
        config()->set("database.default", "legacy_host_sqlite");
        config()->set("database.connections.legacy_host_sqlite", [
            "driver" => "sqlite",
            "database" => $legacyHostDb,
            "prefix" => "",
        ]);

        // Simulate pre-SQLite host DB with all Pasax tables & migrations already recorded
        $pasaxMigPath = realpath(__DIR__ . "/../../../../database/migrations");
        config()->set("pasax.database.connection", "legacy_host_sqlite");
        $this->artisan("migrate", [
            "--database" => "legacy_host_sqlite",
            "--path" => $pasaxMigPath,
            "--realpath" => true,
            "--force" => true,
        ])->assertSuccessful();

        expect(
            DB::connection("legacy_host_sqlite")->table("migrations")->count(),
        )->toBeGreaterThanOrEqual(4);

        DB::connection("legacy_host_sqlite")
            ->table("pasax_logs")
            ->insert([
                "ip_address" => "192.0.2.55",
                "event_type" => "sqli",
                "threat_level" => "critical",
                "path" => "/old-app",
                "created_at" => now(),
                "updated_at" => now(),
            ]);
        DB::connection("legacy_host_sqlite")
            ->table("pasax_blocked_ips")
            ->insert([
                "ip_address" => "192.0.2.55",
                "reason" => "Legacy block preserved",
                "is_active" => 1,
                "created_at" => now(),
                "updated_at" => now(),
            ]);
        DB::connection("legacy_host_sqlite")
            ->table("pasax_settings")
            ->insert([
                "key" => "legacy_preserved_setting",
                "value" => "kept_value",
                "created_at" => now(),
                "updated_at" => now(),
            ]);

        // Now switch Pasax to brand-new empty isolated SQLite and invoke upgrade initializer
        DB::purge("pasax_sqlite");
        config()->set("pasax.database.connection", "pasax_sqlite");
        config()->set("pasax.database.path", $newIsolatedDb);

        $result = PasaxDatabase::ensureIsolatedSchemaReady(true);

        expect($result["migrated"])
            ->toBeTrue()
            ->and($result["copied_rows"])
            ->toBeGreaterThanOrEqual(3)
            ->and(PasaxDatabase::schema()->hasTable("pasax_logs"))
            ->toBeTrue()
            ->and(
                DB::connection("pasax_sqlite")
                    ->table("pasax_logs")
                    ->where("ip_address", "192.0.2.55")
                    ->exists(),
            )
            ->toBeTrue()
            ->and(
                DB::connection("pasax_sqlite")
                    ->table("pasax_blocked_ips")
                    ->where("ip_address", "192.0.2.55")
                    ->exists(),
            )
            ->toBeTrue()
            ->and(
                DB::connection("pasax_sqlite")
                    ->table("pasax_settings")
                    ->where("key", "legacy_preserved_setting")
                    ->value("value"),
            )
            ->toBe("kept_value");
    },
);
