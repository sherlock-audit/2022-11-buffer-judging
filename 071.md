koxuan

high

# Unbounded loop in `_getUnlockedLiquidity` can cause dos

## Summary
A loop will run through all the locked Liquidity and see if it has passed the lockdownPeriod before unlocking it. If there is too many lockedLiquidity, the function will run out of gas when unlocking all the locked liquidity, causing a revert and preventing user from ever unlocking liquidity again.
## Vulnerability Detail
` for (uint256 n = index; n < len; n++) {` will loop through all the lockedLiquidity to determine whether they have passed the lockdownPeriod. A user that stacks up too many locked Liquidity and then unlock it all at once at a later timing will cause the function to revert due to using more gas that the gas block limit of 30 million. This causes a DOS to unlocking liquidity as  there is no way for user to decrease the number of locked liquidity.

```solidity
    function _getUnlockedLiquidity(address account)
        internal
        view
        returns (uint256 unlockedAmount, uint256 nextIndexForUnlock)
    {
        uint256 len = liquidityPerUser[account].lockedAmounts.length;
        unlockedAmount = liquidityPerUser[account].unlockedAmount;
        uint256 index = liquidityPerUser[account].nextIndexForUnlock;
        nextIndexForUnlock = index;
        for (uint256 n = index; n < len; n++) {
            if (
                liquidityPerUser[account].lockedAmounts[n].timestamp +
                    lockupPeriod <=
                block.timestamp
            ) {
                unlockedAmount += liquidityPerUser[account]
                    .lockedAmounts[n]
                    .amount;
                nextIndexForUnlock = n + 1;
            } else {
                break;
            }
        }
```
## Impact
User can never unlock locked liquidities again.
## Code Snippet
[BufferBinaryPool.sol#L262-L285](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L262-L285)
## Tool used

Manual Review

## Recommendation

### Mitigation 1

Consider allowing user to unlock an explicit number of locked liquidity so that even if the number of locked liquidity is big, user can choose to unlock the next few locked liquidity to decrease the number of locked liquidity. 

### Mitigation 2
Consider limiting the number of locked liquidity that user can have. 