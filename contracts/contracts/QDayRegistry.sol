// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title QDayRegistry
/// @notice On-chain record of Q-Day readiness attestations, checked by the chain's own PQC precompiles.
///
/// An attestation is a hybrid-signed (secp256k1 + ML-DSA-87) native QoreChain transaction whose memo
/// reads `qday:v1;<qor1 account>;<grade>;<readiness>;<scan digest>`. Anyone may relay one here: the
/// contract rebuilds nothing on trust. It takes the transaction's hybrid sign-bytes (v2) and its
/// ML-DSA-87 signature, then
///   1. reads the account's registered key from the PQC Key Status precompile (0x0a02) and requires an
///      ML-DSA-87 key with a proven possession,
///   2. checks the signature over the sign-bytes with the PQC Verify precompile (0x0a01),
///   3. parses the sign-bytes itself: this chain's id, the memo (TxBody field 2, which must name this
///      very account in bech32), and the signer's sequence (AuthInfo.signer_infos[0].sequence),
///   4. keeps only a newer sequence than the one on record, so an old attestation cannot replace a newer one.
/// So a record exists only if the account's own post-quantum key signed that grade.
contract QDayRegistry {
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    address internal constant PQC_STATUS = 0x0000000000000000000000000000000000000a02;
    uint8 internal constant ML_DSA_87 = 1;
    bytes23 internal constant SIGN_BYTES_V2 = "qorechain-pqc-hybrid-v2";
    bytes internal constant MEMO_PREFIX = "qday:v1;";
    bytes internal constant BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    bytes internal constant HRP = "qor";

    struct Attestation {
        bytes32 signBytesHash; // keccak256 of the hybrid sign-bytes the account's ML-DSA-87 key signed
        bytes32 keyHash; // keccak256 of that ML-DSA-87 public key
        bytes32 nativeTx; // the native transaction's hash, as given by the relayer (Verify re-checks it)
        uint64 sequence; // the account's sequence in that transaction
        uint64 blockNumber; // EVM block of the record
        uint8 readiness; // 0 to 100
        bytes1 grade; // A, B, C, D or F
        bytes6 scanDigest; // the memo's 12 hex characters
    }

    /// The chain whose sign-bytes are accepted (`qorechain-diana` on testnet).
    string public chainId;
    mapping(address => Attestation) public latest;
    mapping(address => uint32) public count;

    event Recorded(
        address indexed account,
        bytes32 indexed nativeTx,
        bytes1 grade,
        uint8 readiness,
        bytes6 scanDigest,
        uint64 sequence,
        address relayer
    );

    error NoPqcKey();
    error NoProofOfPossession();
    error BadSignature();
    error BadSignBytes();
    error WrongChain();
    error BadMemo();
    error NotNewer();

    constructor(string memory chainId_) {
        chainId = chainId_;
    }

    /// @notice Record an attestation for `account` from its signed transaction. Callable by anyone.
    /// @param signBytes The transaction's hybrid sign-bytes (v2), which the ML-DSA-87 key signed.
    /// @param pqcSignature The ML-DSA-87 signature from the transaction's PQC extension.
    /// @param nativeTx The native transaction hash, kept as a pointer for readers.
    function record(address account, bytes calldata signBytes, bytes calldata pqcSignature, bytes32 nativeTx) external {
        bytes memory pubkey = _provenKey(account);
        if (!_pqcVerify(pubkey, pqcSignature, signBytes)) revert BadSignature();

        (bytes calldata body, bytes calldata authInfo) = _split(signBytes);
        (bool hasMemo, bytes calldata memo) = _lastBytesField(body, 2);
        if (!hasMemo) revert BadMemo();
        (bytes1 grade, uint8 readiness, bytes6 digest) = _parseMemo(memo, account);
        uint64 sequence = _firstSignerSequence(authInfo);

        if (count[account] != 0 && sequence <= latest[account].sequence) revert NotNewer();
        latest[account] = Attestation({
            signBytesHash: keccak256(signBytes),
            keyHash: keccak256(pubkey),
            nativeTx: nativeTx,
            sequence: sequence,
            blockNumber: uint64(block.number),
            readiness: readiness,
            grade: grade,
            scanDigest: digest
        });
        unchecked {
            count[account] += 1;
        }
        emit Recorded(account, nativeTx, grade, readiness, digest, sequence, msg.sender);
    }

    /// @notice True when `account` has a recorded readiness of at least `minReadiness` and still holds
    /// the same proven ML-DSA-87 key that signed it. Other contracts can gate on this.
    function isReady(address account, uint8 minReadiness) external view returns (bool) {
        if (count[account] == 0) return false;
        Attestation storage a = latest[account];
        if (a.readiness < minReadiness) return false;
        (bool ok, bytes memory ret) = PQC_STATUS.staticcall(abi.encodeWithSignature("pqcKeyStatus(address)", account));
        if (!ok || ret.length < 128) return false;
        (bool registered, uint8 alg, bytes memory pubkey, bool proven) = abi.decode(ret, (bool, uint8, bytes, bool));
        return registered && proven && alg == ML_DSA_87 && keccak256(pubkey) == a.keyHash;
    }

    /// @notice The bech32 `qor1…` form of an account, as its memo must name it.
    function qorAddress(address account) external pure returns (string memory) {
        return string(_bech32(account));
    }

    // ── precompiles ──────────────────────────────────────────────────────────

    function _provenKey(address account) internal view returns (bytes memory pubkey) {
        (bool ok, bytes memory ret) = PQC_STATUS.staticcall(abi.encodeWithSignature("pqcKeyStatus(address)", account));
        if (!ok || ret.length < 128) revert NoPqcKey();
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = abi.decode(ret, (bool, uint8, bytes, bool));
        if (!registered || alg != ML_DSA_87 || pubkey.length == 0) revert NoPqcKey();
        if (!proven) revert NoProofOfPossession();
    }

    function _pqcVerify(bytes memory pubkey, bytes calldata sig, bytes calldata message) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            PQC_VERIFY.staticcall(abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", pubkey, sig, message));
        return ok && ret.length >= 32 && abi.decode(ret, (bool));
    }

    // ── sign-bytes v2 ────────────────────────────────────────────────────────
    // "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖ BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
    // with B0 the TxBody without its PQC extension and A the AuthInfo.

    function _split(bytes calldata sb) internal view returns (bytes calldata body, bytes calldata authInfo) {
        if (sb.length < 39 || bytes23(sb[0:23]) != SIGN_BYTES_V2) revert BadSignBytes();
        uint256 p = 23;
        uint256 n = uint64(bytes8(sb[p:p + 8]));
        p += 8;
        bytes memory id = bytes(chainId);
        if (n != id.length || keccak256(sb[p:p + n]) != keccak256(id)) revert WrongChain();
        p += n;
        n = uint32(bytes4(sb[p:p + 4]));
        p += 4;
        body = sb[p:p + n];
        p += n;
        n = uint32(bytes4(sb[p:p + 4]));
        p += 4;
        authInfo = sb[p:p + n];
        if (p + n != sb.length) revert BadSignBytes();
    }

    // ── protobuf (top-level fields only) ─────────────────────────────────────

    function _varint(bytes calldata b, uint256 p) internal pure returns (uint256 v, uint256) {
        for (uint256 shift; shift < 64; shift += 7) {
            uint8 x = uint8(b[p++]);
            v |= uint256(x & 0x7f) << shift;
            if (x < 0x80) return (v, p);
        }
        revert BadSignBytes();
    }

    /// Skip one field's value; returns the new position and, for length-delimited fields, its slice.
    function _skip(bytes calldata b, uint256 p, uint256 wireType) internal pure returns (uint256, uint256 start, uint256 len) {
        if (wireType == 0) {
            (, p) = _varint(b, p);
        } else if (wireType == 2) {
            (len, p) = _varint(b, p);
            start = p;
            p += len;
        } else if (wireType == 1) {
            p += 8;
        } else if (wireType == 5) {
            p += 4;
        } else {
            revert BadSignBytes();
        }
        if (p > b.length) revert BadSignBytes();
        return (p, start, len);
    }

    /// The last occurrence of a length-delimited field (protobuf: the last one wins for a scalar).
    function _lastBytesField(bytes calldata b, uint256 field) internal pure returns (bool found, bytes calldata out) {
        out = b[0:0];
        uint256 p;
        while (p < b.length) {
            uint256 key;
            uint256 start;
            uint256 len;
            (key, p) = _varint(b, p);
            (p, start, len) = _skip(b, p, key & 7);
            if (key >> 3 == field && key & 7 == 2) {
                found = true;
                out = b[start:start + len];
            }
        }
    }

    /// AuthInfo.signer_infos[0].sequence (field 1, then field 3); 0 when absent.
    function _firstSignerSequence(bytes calldata authInfo) internal pure returns (uint64) {
        uint256 p;
        while (p < authInfo.length) {
            uint256 key;
            uint256 start;
            uint256 len;
            (key, p) = _varint(authInfo, p);
            (p, start, len) = _skip(authInfo, p, key & 7);
            if (key == (1 << 3) | 2) return _sequenceOf(authInfo[start:start + len]);
        }
        revert BadSignBytes();
    }

    function _sequenceOf(bytes calldata signerInfo) internal pure returns (uint64 sequence) {
        uint256 p;
        while (p < signerInfo.length) {
            uint256 key;
            (key, p) = _varint(signerInfo, p);
            if (key == (3 << 3)) {
                uint256 v;
                (v, p) = _varint(signerInfo, p);
                sequence = uint64(v);
            } else {
                (p,,) = _skip(signerInfo, p, key & 7);
            }
        }
    }

    // ── memo ─────────────────────────────────────────────────────────────────

    function _parseMemo(bytes calldata memo, address account)
        internal
        pure
        returns (bytes1 grade, uint8 readiness, bytes6 digest)
    {
        bytes memory head = abi.encodePacked(MEMO_PREFIX, _bech32(account), ";");
        uint256 p = head.length;
        // head ‖ grade ‖ ";" ‖ 1-3 digits ‖ ";" ‖ 12 lowercase hex
        if (memo.length < p + 16 || memo.length > p + 18 || keccak256(memo[0:p]) != keccak256(head)) revert BadMemo();
        grade = memo[p];
        if (!(grade == "A" || grade == "B" || grade == "C" || grade == "D" || grade == "F") || memo[p + 1] != ";") {
            revert BadMemo();
        }
        p += 2;
        uint256 r;
        uint256 digits;
        while (p < memo.length && memo[p] != ";") {
            uint8 c = uint8(memo[p]);
            if (c < 0x30 || c > 0x39 || digits == 3 || (digits == 1 && r == 0)) revert BadMemo();
            r = r * 10 + (c - 0x30);
            digits++;
            p++;
        }
        if (digits == 0 || r > 100 || p + 13 != memo.length) revert BadMemo();
        p++;
        uint48 d;
        for (uint256 i; i < 12; i++) {
            uint8 c = uint8(memo[p + i]);
            uint8 nib;
            if (c >= 0x30 && c <= 0x39) nib = c - 0x30;
            else if (c >= 0x61 && c <= 0x66) nib = c - 0x57;
            else revert BadMemo();
            d = (d << 4) | nib;
        }
        return (grade, uint8(r), bytes6(d));
    }

    // ── bech32 (BIP-173) of a 20-byte account with the `qor` prefix ──────────

    function _polymodStep(uint256 pre) private pure returns (uint256 chk) {
        uint256 b = pre >> 25;
        chk = (pre & 0x1ffffff) << 5;
        if (b & 1 != 0) chk ^= 0x3b6a57b2;
        if (b & 2 != 0) chk ^= 0x26508e6d;
        if (b & 4 != 0) chk ^= 0x1ea119fa;
        if (b & 8 != 0) chk ^= 0x3d4233dd;
        if (b & 16 != 0) chk ^= 0x2a1462b3;
    }

    function _bech32(address account) internal pure returns (bytes memory out) {
        uint256 v = uint160(account);
        uint256[32] memory data; // 160 bits = 32 groups of 5
        for (uint256 i; i < 32; i++) {
            data[31 - i] = (v >> (5 * i)) & 31;
        }
        uint256 chk = 1;
        for (uint256 i; i < HRP.length; i++) chk = _polymodStep(chk) ^ (uint8(HRP[i]) >> 5);
        chk = _polymodStep(chk);
        for (uint256 i; i < HRP.length; i++) chk = _polymodStep(chk) ^ (uint8(HRP[i]) & 31);
        for (uint256 i; i < 32; i++) chk = _polymodStep(chk) ^ data[i];
        for (uint256 i; i < 6; i++) chk = _polymodStep(chk);
        chk ^= 1;

        out = new bytes(HRP.length + 1 + 32 + 6);
        for (uint256 i; i < HRP.length; i++) out[i] = HRP[i];
        uint256 o = HRP.length;
        out[o++] = "1";
        for (uint256 i; i < 32; i++) out[o++] = BECH32_CHARSET[data[i]];
        for (uint256 i; i < 6; i++) out[o++] = BECH32_CHARSET[(chk >> (5 * (5 - i))) & 31];
    }
}
