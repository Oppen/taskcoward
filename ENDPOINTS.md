According to Gemini:

Here's a breakdown of each endpoint:

**1. AddVersion**

*   **Path:** `<base_url>/v1/client/add-version/<parentVersionId>`
    *   `<parentVersionId>` is a UUID.
*   **HTTP Method:** `POST`
*   **Expected Headers:**
    *   `Content-Type`: `application/vnd.taskchampion.history-segment`
    *   `X-Client-Id`: Client UUID
*   **Request Body:** Encrypted version data (history segment)
*   **Responses:**
    *   **200 OK (Success):**
        *   Condition: Version is accepted.
        *   Response Body: Empty
        *   Set Headers:
            *   `X-Version-Id`: New version UUID
            *   `X-Snapshot-Request`: `urgency=low` or `urgency=high` (optional, depending on snapshot urgency)
    *   **409 CONFLICT:**
        *   Condition: Version is not accepted due to conflict.
        *   Response Body: Empty
        *   Set Headers:
            *   `X-Parent-Version-Id`: Expected parent version UUID
    *   **400 BAD REQUEST:**
        *   Condition: Bad content-type or empty body.
        *   Response Body: Error message
    *   **Other 4xx or 5xx:** Other errors as defined in HTTP specification.
*   **Code:** `task/taskchampion-sync-server/server/src/api/add_version.rs#L28`

**2. GetChildVersion**

*   **Path:** `<base_url>/v1/client/get-child-version/<parentVersionId>`
    *   `<parentVersionId>` is a UUID.
*   **HTTP Method:** `GET`
*   **Expected Headers:**
    *   `X-Client-Id`: Client UUID
*   **Responses:**
    *   **200 OK (Success):**
        *   Condition: Child version found.
        *   Response Body: Encrypted version data (history segment)
        *   Set Headers:
            *   `X-Version-Id`: Version UUID
            *   `X-Parent-Version-Id`: Parent version UUID
            *   `Content-Type`: `application/vnd.taskchampion.history-segment`
    *   **404 NOT FOUND:**
        *   Condition: No such child version exists (client is up-to-date).
        *   Response Body: Empty
    *   **410 GONE:**
        *   Condition: Version has been deleted (synchronization error).
        *   Response Body: Empty
    *   **Other 4xx or 5xx:** Other errors as defined in HTTP specification.
*   **Code:** `task/taskchampion-sync-server/server/src/api/get_child_version.rs#L17`

**3. AddSnapshot**

*   **Path:** `<base_url>/v1/client/add-snapshot/<versionId>`
    *   `<versionId>` is a UUID.
*   **HTTP Method:** `POST`
*   **Expected Headers:**
    *   `Content-Type`: `application/vnd.taskchampion.snapshot`
    *   `X-Client-Id`: Client UUID
*   **Request Body:** Encrypted snapshot data
*   **Responses:**
    *   **200 OK (Success):**
        *   Condition: Snapshot is accepted (even if not stored).
        *   Response Body: Empty
    *   **400 BAD REQUEST:**
        *   Condition: Invalid version or bad content-type.
        *   Response Body: Error message
*   **Code:** `task/taskchampion-sync-server/server/src/api/add_snapshot.rs#L26`

**4. GetSnapshot**

*   **Path:** `<base_url>/v1/client/snapshot`
*   **HTTP Method:** `GET`
*   **Expected Headers:**
    *   `X-Client-Id`: Client UUID
*   **Responses:**
    *   **200 OK (Success):**
        *   Condition: Snapshot exists.
        *   Response Body: Encrypted snapshot data
        *   Set Headers:
            *   `Content-Type`: `application/vnd.taskchampion.snapshot`
            *   `X-Version-Id`: Version UUID of the snapshot
    *   **404 NOT FOUND:**
        *   Condition: No snapshot exists.
        *   Response Body: Empty
*   **Code:** `task/taskchampion-sync-server/server/src/api/get_snapshot.rs#L16`

**General Notes:**

*   All endpoints use the `X-Client-Id` header to identify the client.
*   Data is expected to be encrypted by the client before transmission.
*   The server may return other 4xx or 5xx HTTP status codes for various errors.
*   The `base_url` should use HTTPS for security.

## Abridged

**AddVersion**

*   200: \['X-Version-Id', 'X-Snapshot-Request']
*   409: \['X-Parent-Version-Id']
*   400: \[ ]

**GetChildVersion**

*   200: \['X-Version-Id', 'X-Parent-Version-Id', 'Content-Type', 'Content-Length'] (BODY)
*   404: \[ ]
*   410: \[ ]

**AddSnapshot**

*   200: \[ ]
*   400: \[ ]

**GetSnapshot**

*   200: \['Content-Type', 'X-Version-Id', 'Content-Length'] (BODY)
*   404: \[ ]
