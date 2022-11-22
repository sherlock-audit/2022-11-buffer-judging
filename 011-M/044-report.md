ctf_sec

medium

# Nonce is missing: publisher's signature can be reused.

## Summary

Nonce is missing: publisher's signature can be reused.

## Vulnerability Detail

In BufferRouter.sol, after the a trade is queued, the keeper needs to call resolveQueueTrades.sol

The first step is validate the signer's signature.

```solidity
bool isSignerVerifed = _validateSigner(
    currentParams.timestamp,
    currentParams.asset,
    currentParams.price,
    currentParams.signature
);
// Silently fail if the signature doesn't match
if (!isSignerVerifed) {
    emit FailResolve(
        currentParams.queueId,
        "Router: Signature didn't match"
    );
    continue;
}
```

which calls:

```solidity
    function _validateSigner(
        uint256 timestamp,
        address asset,
        uint256 price,
        bytes memory signature
    ) internal view returns (bool) {
        bytes32 digest = ECDSA.toEthSignedMessageHash(
            keccak256(abi.encodePacked(timestamp, asset, price))
        );
        address recoveredSigner = ECDSA.recover(digest, signature);
        return recoveredSigner == publisher;
    }
```

We see that the nonce is missing when generating the signature. Another user can copy the signature generated by the publisher and reuse the signature to queue another trade. 

same issue exists when unlockOptions is called by keeper when we are validating the signature.

```solidity
    (, , , , , uint256 expiration, , , ) = optionsContract.options(
        params.optionId
    );

    bool isSignerVerifed = _validateSigner(
        params.expiryTimestamp,
        params.asset,
        params.priceAtExpiry,
        params.signature
    );
```

## Impact

publisher's and keeper's signatures can be reused to launch a signature replay attack.

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L143-L156

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L259-L272

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L196-L209

## Tool used

Manual Review

## Recommendation

We recommend the project add nonce to signature schema and increment the nonce each time to prevent signature replay. 