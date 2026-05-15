# Security Specification for Vas-y Padel Academy

## Data Invariants
1. **Relational Integrity**: A `Package` MUST belong to a valid `Player`. A `Session` MUST belong to a valid `Package` and `Player`.
2. **Identity Integrity**: Every record created MUST have an `ownerId` matching the authenticated user's UID (unless master data).
3. **Role-Based Access**: Only `admin` role (verified via `/appUsers/{uid}`) can modify master data (Locations, Levels, etc.).
4. **Immutability**: `createdAt` and `playerId` in `Package` are immutable after creation.
5. **PII Isolation**: Player contact info (email/phone) is restricted to the owner or assigned coach.

## The Dirty Dozen Payloads (Red Team Tests)

### 1. Identity Spoofing (PII Access)
**Target**: `get /players/player123`
**Attacker**: `auth.uid = 'attacker_uid'` (Not owner/coach)
**Expected**: `PERMISSION_DENIED`

### 2. Identity Spoofing (Owner Hijack)
**Target**: `create /players/new_player`
**Payload**:
```json
{
  "name": "Jane Doe",
  "ownerId": "victim_uid",
  "locationId": "loc1"
}
```
**Expected**: `PERMISSION_DENIED` (ownerId must match auth.uid)

### 3. Ghost Field Injection
**Target**: `update /packages/pkg1`
**Payload**:
```json
{
  "isFree": true,
  "status": "Paid"
}
```
**Expected**: `PERMISSION_DENIED` (isFree is not in schema)

### 4. Invalid Type (Financial Poisoning)
**Target**: `create /payments/pay1`
**Payload**:
```json
{
  "packageId": "pkg1",
  "amount": "one thousand",
  "date": "2026-05-14"
}
```
**Expected**: `PERMISSION_DENIED` (amount must be number)

### 5. ID Poisoning (DOS)
**Target**: `create /sessions/{extremely_long_id_...}`
**Expected**: `PERMISSION_DENIED` (isValidId regex/size check)

### 6. State Shortcutting (Terminal State bypass)
**Target**: `update /packages/pkg1` (where status is already 'Paid')
**Payload**:
```json
{
  "status": "Not Paid"
}
```
**Expected**: `PERMISSION_DENIED` (Terminal state locking)

### 7. Resource Exhaustion
**Target**: `update /players/player1`
**Payload**:
```json
{
  "name": "A".repeat(10000)
}
```
**Expected**: `PERMISSION_DENIED` (String size limit)

### 8. Cross-User Mutation
**Target**: `update /sessions/session_of_other_coach`
**Payload**:
```json
{
  "status": "Attended"
}
```
**Expected**: `PERMISSION_DENIED`

### 9. Relational Sync Failure (Phantom Parent)
**Target**: `create /packages/pkg1`
**Payload**:
```json
{
  "playerId": "non_existent_player",
  "packageTypeCode": "G2",
  "startDate": "2026-05-14"
}
```
**Expected**: `PERMISSION_DENIED` (exists() check fails)

### 10. Immutable Field Change
**Target**: `update /packages/pkg1`
**Payload**:
```json
{
  "playerId": "new_player_id"
}
```
**Expected**: `PERMISSION_DENIED`

### 11. PII Blanket Read (List Scraping)
**Target**: `list /players` (without where ownerId == auth.uid)
**Expected**: `PERMISSION_DENIED`

### 12. Negative Payment
**Target**: `create /payments/pay2`
**Payload**:
```json
{
  "packageId": "pkg1",
  "amount": -100,
  "date": "2026-05-14"
}
```
**Expected**: `PERMISSION_DENIED` (amount must be > 0)

## The Test Runner
A `firestore.rules.test.ts` will be implemented using the Firebase Rules Emulator to verify these scenarios.
