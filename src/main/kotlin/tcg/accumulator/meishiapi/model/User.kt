package tcg.accumulator.meishiapi.model

import java.time.OffsetDateTime
import java.util.UUID

enum class Role {
    USER,
    ADMIN,
}

enum class Status {
    ACTIVE,
    FROZEN,
}

data class User(
    val id: UUID,
    val nickname: String?,
    val role: Role,
    val status: Status,
    val activationKey: UUID,
    val activatedAt: OffsetDateTime?,
    val createdAt: OffsetDateTime,
    val email: String? = null,
    val phone: String? = null,
    val firstName: String? = null,
    val lastName: String? = null,
    val addressLine1: String? = null,
    val addressLine2: String? = null,
    val postalCode: String? = null,
    val city: String? = null,
    val country: String? = null,
) {
    val isActivated: Boolean get() = activatedAt != null
}
