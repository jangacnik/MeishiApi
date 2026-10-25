package tcg.accumulator.meishiapi

data class AppConfig(
    val httpPort: Int,
    val dbHost: String,
    val dbPort: Int,
    val dbName: String,
    val dbUser: String,
    val dbPassword: String,
    val jwtSecret: String,
    val adminNickname: String,
    val adminPassword: String,
) {
    val jdbcUrl: String get() = "jdbc:postgresql://$dbHost:$dbPort/$dbName"

    companion object {
        private const val MIN_JWT_SECRET_LENGTH = 32
        private const val KNOWN_DEV_JWT_SECRET = "dev-secret-change-me"
        private const val KNOWN_DEFAULT_ADMIN_PASSWORD = "admin"

        fun fromEnv(getenv: (String) -> String? = System::getenv): AppConfig {
            fun env(name: String, default: String) = getenv(name) ?: default
            fun required(name: String) = getenv(name)?.takeIf { it.isNotBlank() }
                ?: error("required environment variable $name is not set")

            val jwtSecret = required("JWT_SECRET")
            check(jwtSecret.toByteArray().size >= MIN_JWT_SECRET_LENGTH && jwtSecret != KNOWN_DEV_JWT_SECRET) {
                "JWT_SECRET must be at least $MIN_JWT_SECRET_LENGTH bytes and not the known development value"
            }
            val adminPassword = required("ADMIN_PASSWORD")
            check(adminPassword != KNOWN_DEFAULT_ADMIN_PASSWORD) {
                "ADMIN_PASSWORD must not be the default value '$KNOWN_DEFAULT_ADMIN_PASSWORD'"
            }

            return AppConfig(
                httpPort = env("HTTP_PORT", "8080").toInt(),
                dbHost = env("DB_HOST", "localhost"),
                dbPort = env("DB_PORT", "5432").toInt(),
                dbName = env("DB_NAME", "meishi"),
                dbUser = env("DB_USER", "meishi"),
                dbPassword = required("DB_PASSWORD"),
                jwtSecret = jwtSecret,
                adminNickname = env("ADMIN_NICKNAME", "admin"),
                adminPassword = adminPassword,
            )
        }
    }
}
