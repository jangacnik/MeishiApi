package tcg.accumulator.meishiapi.model

import java.time.OffsetDateTime
import java.util.UUID

enum class Role {
    USER,
    ADMIN,
}

data class User(
    val id: UUID,
    val nickname: String?,
    val role: Role,
    val activationKey: UUID,
    val activatedAt: OffsetDateTime?,
    val createdAt: OffsetDateTime,
) {
    val isActivated: Boolean get() = activatedAt != null
}
