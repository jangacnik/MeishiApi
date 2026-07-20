package tcg.accumulator.meishiapi

import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject

data class AdminUserConfig(val nickname: String, val password: String)

data class AppConfig(
    val httpPort: Int,
    val dbHost: String,
    val dbPort: Int,
    val dbName: String,
    val dbUser: String,
    val dbPassword: String,
    val jwtSecret: String,
    val adminUsers: List<AdminUserConfig>,
) {
    val jdbcUrl: String get() = "jdbc:postgresql://$dbHost:$dbPort/$dbName"

    companion object {
        private const val DEFAULT_ADMIN_USERS = """[{"nickname":"admin","password":"admin"}]"""

        fun fromEnv(): AppConfig {
            fun env(name: String, default: String) = System.getenv(name) ?: default

            return AppConfig(
                httpPort = env("HTTP_PORT", "8080").toInt(),
                dbHost = env("DB_HOST", "localhost"),
                dbPort = env("DB_PORT", "5432").toInt(),
                dbName = env("DB_NAME", "meishi"),
                dbUser = env("DB_USER", "meishi"),
                dbPassword = env("DB_PASSWORD", "meishi"),
                jwtSecret = env("JWT_SECRET", "dev-secret-change-me"),
                adminUsers = parseAdminUsers(env("ADMIN_USERS", DEFAULT_ADMIN_USERS)),
            )
        }

        /**
         * ADMIN_USERS is a JSON array of {"nickname", "password"} - config-only
         * admin accounts, ensured to exist at startup independent of the normal
         * registration/role-management API. Never committed: sourced from a
         * masked+protected GitLab CI/CD variable in real deployments.
         */
        fun parseAdminUsers(raw: String): List<AdminUserConfig> =
            JsonArray(raw).map { it as JsonObject }.map {
                AdminUserConfig(nickname = it.getString("nickname"), password = it.getString("password"))
            }
    }
}
