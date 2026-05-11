// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Base64URL - Minimal base64url encoding for WebAuthn challenge verification
/// @notice Self-contained; avoids external dependencies (Solady, OZ).
library Base64URL {
    bytes private constant _TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// @notice Encode arbitrary bytes to base64url (RFC 4648, no padding).
    function encode(bytes memory data) internal pure returns (string memory) {
        uint256 len = data.length;
        uint256 outLen = (len * 4 + 2) / 3; // ceil(len*4/3), no padding
        bytes memory out = new bytes(outLen);

        uint256 i = 0;
        uint256 j = 0;
        for (; i + 3 <= len; i += 3) {
            bytes4 quad = _encodeTriplet(uint8(data[i]), uint8(data[i + 1]), uint8(data[i + 2]));
            out[j] = quad[0];
            out[j + 1] = quad[1];
            out[j + 2] = quad[2];
            out[j + 3] = quad[3];
            j += 4;
        }
        if (i < len) {
            uint8 b0 = uint8(data[i]);
            uint8 b1 = i + 1 < len ? uint8(data[i + 1]) : 0;
            bytes4 quad = _encodeTriplet(b0, b1, 0);
            out[j] = quad[0];
            out[j + 1] = quad[1];
            if (i + 1 < len) {
                out[j + 2] = quad[2];
                j += 3;
            } else {
                j += 2;
            }
        }
        assembly { mstore(out, j) } // trim to actual used length
        return string(out);
    }

    function _encodeTriplet(uint8 b0, uint8 b1, uint8 b2) private pure returns (bytes4) {
        uint24 combined = (uint24(b0) << 16) | (uint24(b1) << 8) | uint24(b2);
        return bytes4(
            (_ENCODE_INDEX(combined >> 18) << 24) | (_ENCODE_INDEX((combined >> 12) & 0x3F) << 16)
                | (_ENCODE_INDEX((combined >> 6) & 0x3F) << 8) | _ENCODE_INDEX(combined & 0x3F)
        );
    }

    function _ENCODE_INDEX(uint256 idx) private pure returns (bytes1) {
        return _TABLE[idx];
    }
}
