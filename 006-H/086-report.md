kaliberpoziomka

high

# Keeper can unlock trades with expiry price taken from other trade

---
name: Audit item
about: These are the audit items that end up in the report
title: Keeper can unlock trades with expiry price taken from other trade
labels: High
assignees: kaliberpoziomka
---

## Summary

Context: `BufferRouter.sol`
A malicious keeper can unlock the **trade** with different price, preventing the **trade** from being excercised. 

## Vulnerability Detail

Malicious keeper can call  the function `unlockOptions(...)` with input crafted in such a way, that object `CloseTradeParams` contains `optionId` of one trade, but the rest of the data (`expiryTimestamp`, `asset`, `priceAtExpiry` and `signature`) comes from another trade and is already validly signed by the publisher. It is possible, because signed data does not include `optionId`. The only data that must match for both trades is the `expiryTimestamp`, since it is compared with `expiration` at [L211](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L211).

## Impact

Since trade can be unlocked with chosen `priceAtExpiration` value, the malicious keeper may prevent the trade from being executed by manipilation the `priceAtExpiration` value to not satisfy the condition in `BufferBinaryOptions::unlock(...)` ([L166-167](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L166-L167)).

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L190-L232

```solidity
function unlockOptions(CloseTradeParams[] calldata optionData) external {
      _validateKeeper();

      uint32 arrayLength = uint32(optionData.length);
      for (uint32 i = 0; i < arrayLength; i++) {
          CloseTradeParams memory params = optionData[i];
          IBufferBinaryOptions optionsContract = IBufferBinaryOptions(
              params.asset
          );
          (, , , , , uint256 expiration, , , ) = optionsContract.options(
              params.optionId
          );

          bool isSignerVerifed = _validateSigner(
              params.expiryTimestamp,
              params.asset,
              params.priceAtExpiry,
              params.signature
          );

          // Silently fail if the timestamp of the signature is wrong
          if (expiration != params.expiryTimestamp) {
              emit FailUnlock(params.optionId, "Router: Wrong price");
              continue;
          }

          // Silently fail if the signature doesn't match
          if (!isSignerVerifed) {
              emit FailUnlock(
                  params.optionId,
                  "Router: Signature didn't match"
              );
              continue;
          }

          try
              optionsContract.unlock(params.optionId, params.priceAtExpiry)
          {} catch Error(string memory reason) {
              emit FailUnlock(params.optionId, reason);
              continue;
          }
      }
  }
```

## Tool used

Manual Review

## Recommendation

Consider including the `optionId` into the message digest signed by the publisher.