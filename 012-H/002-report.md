rvierdiiev

high

# Keeper can manipulate with trading results

## Summary
Because the protocol fully trust to keepers it's possible for them to manipulate with trades by providing incorrect publisher's results.
## Vulnerability Detail
Keeper can be anyone who should track new trades and also close old trades.
Currently, the protocol fully trust the keeper and only check that the data from publisher is indeed signed by publisher.

Let's look into BufferRouter.unlockOptions function.
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

When keeper provides close trading params, the only data signed by publisher is expiryTimestamp, asset, priceAtExpiry.
```solidity
            bool isSignerVerifed = _validateSigner(
                params.expiryTimestamp,
                params.asset,
                params.priceAtExpiry,
                params.signature
            );
```

The id of option to close is included by keeper and is not controlled by publisher.
Later there is only 1 check if `expiration != params.expiryTimestamp`.
Pls, note that there is no check that option trading pair is same as publishers oracle price.

This allows keeper to fully drain all funds from the pool
1. keeper initiate trade from another account for all available amount of pool
2. then keeper starts this trade, using `resolveQueuedTrades`
3. at expiration time of option keeper provides price for another asset with same expiration as the created option(but he will provide price that will 100% win)
4. keeper receive all money from pool

Same problems has `resolveQueuedTrades` function as it also doesn't check that the trade pair is same as provided publishers oracle price. That means that keeper can full slippage protection with providing another asset's prices.
I believe that this is also has the same root, that's why i do not create separate report for that.
## Impact
Keeper can full protocol and drain all funds from pool.
## Code Snippet
https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L190-L232
## Tool used

Manual Review

## Recommendation
The check should be added that the price, provided by keeper is for the same pair that user is trading.