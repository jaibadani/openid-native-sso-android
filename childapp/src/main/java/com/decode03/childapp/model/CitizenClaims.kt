package com.decode03.childapp.model

import org.json.JSONObject

data class CitizenClaims(
    val sub: String,
    val name: String?,
    val email: String?,
    val phoneNumber: String?,
    val birthdate: String?,
    val gender: String?,
    val rawJson: JSONObject
) {
    companion object {
        fun fromJson(json: JSONObject): CitizenClaims {
            return CitizenClaims(
                sub = json.optString("sub", "Unknown"),
                name = json.optString("name").ifBlank { null },
                email = json.optString("email").ifBlank { null },
                phoneNumber = json.optString("phone_number").ifBlank { null },
                birthdate = json.optString("birthdate").ifBlank { null },
                gender = json.optString("gender").ifBlank { null },
                rawJson = json
            )
        }
    }
}
