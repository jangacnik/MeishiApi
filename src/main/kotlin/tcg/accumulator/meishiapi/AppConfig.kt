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
                adminNickname = env("ADMIN_NICKNAME", "admin"),
                adminPassword = env("ADMIN_PASSWORD", "admin"),
            )
        }
    }
}
