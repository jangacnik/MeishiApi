package tcg.accumulator.meishiapi.http

class ApiException(val status: Int, message: String) : RuntimeException(message)
