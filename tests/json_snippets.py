valid_rpt = {
    "upgraded": "false",
    "access_token": "fake oauth token",
    "expires_in": 300,
    "refresh_expires_in": 1800,
    "refresh_token": "fake refresh token",
    "token_type": "Bearer",
    "not-before-policy": 1559124935
}

decoded_jwt_with_permission_test1_and_test2 = {
    "authorization": {
        "permissions": [
            {
                "rsid": "6c6b0f5b-975e-4401-95ce-d68fba0e8a5a",
                "rsname": "test2"
            },
            {
                "rsid": "38bfa5c5-33fc-430e-a552-1363be7d8ffe",
                "rsname": "test1"
            }
        ]
    }
}

decoded_jwt_with_permission_test3 = {
    "authorization": {
        "permissions": [
            {
                "rsid": "bbc80f5b-975e-9672-82dd-d68fba0e8a5a",
                "rsname": "test3"
            }
        ]
    }
}

resource_test2 = {
    "_id": "6c6b0f5b-975e-4401-95ce-d68fba0e8a5a",
    "uris": [
        "/test2"
    ]
}
resource_test1 = {
    "_id": "38bfa5c5-33fc-430e-a552-1363be7d8ffe",
    "uris": [
        "/test1"
    ]
}
resource_test3 = {
    "_id": "bbc80f5b-975e-9672-82dd-d68fba0e8a5a",
    "uris": [
        "/test3"
    ]
}
access_token = "fake oauth token"
