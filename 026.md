peanuts

high

# First index for optionId is wrongly assigned in createFromRouter()

## Summary

Wrong callibration of optionId leads to router failing to write any option.

## Vulnerability Detail

When a user creates an option using [createFromRouter()](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L107) in BufferBinaryOptions, the optionId is assigned. The optionId for the first option contract will be 1 because of the call to [_generateTokenId()](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L123) will increment the optionId by 1 immediately

    function _generateTokenId() internal returns (uint256) {
        return nextTokenId++;
    }

The optionId is then [passed as a param in createFromRouter()](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L142) and used in the function [lock](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L149-L154). The lock function in BufferBinaryPool checks if id == lockedLiquidity[msg.sender].length, before pushing the struct LockedLiquidity(x,y,z) into the mapping lockedLiquidity. If no options have been written yet, the lockedLiquidity[msg.sender] length should be 0, but id will start with 1.

        require(id == lockedLiquidity[msg.sender].length, "Pool: Wrong id");

Since 1 != 0, the require check fails and the function reverts.

## Impact

No options can be created due to requirement check failure.

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L123-L142

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L149-L154

## Tool used

Manual Review, Remix IDE

## Recommendation

Make sure the optionId and lockedLiquidity.length is the same for every user.