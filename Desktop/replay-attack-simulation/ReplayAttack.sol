// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReplayAttack {
    mapping(address => uint256) public nonces;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(
        address recipient,
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) public {
        require(msg.sender == owner, "Only owner can call this function");
        require(
            nonce > nonces[msg.sender],
            "Nonce must be greater than previous nonce"
        );
        nonces[msg.sender] = nonce;

        // Hash the transaction data
        bytes32 hash = keccak256(abi.encode(recipient, amount, nonce));

        // Verify the signature
        address signer = recoverSigner(hash, signature);
        require(signer == owner, "Signature is not valid");

        // Transfer the funds
        payable(recipient).transfer(amount);
    }

    function recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");

        return ecrecover(hash, v, r, s);
    }
}
