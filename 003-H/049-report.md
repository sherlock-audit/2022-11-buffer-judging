0x4non

medium

# Use `_safeMint()` instead of `_mint()`

## Summary
OpenZeppelin recommends the usage of `_safeMint()` instead of `_mint()`. If the recipient is a contract, `safeMint()` checks whether they can handle ERC721 tokens.

## Vulnerability Detail
`_mint` will not check if the recipient knows how to handle the NFT. On the other hand, `safeMint()` checks whether they can handle ERC721 tokens.

## Impact
If you use `_mint` and the contract recipient of the NFT its not prepared the NFT could be locked forever inside the contract.
Take in consideration that this might add a reentrancy issue, so add the `nonReentrant` modifier. You are importing the `ReentrancyGuard` but not using this modifier

## Code Snippet
[BufferBinaryOptions.sol#L126](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L126)

## Tool used

Manual Review

## Recommendation
Change [BufferBinaryOptions.sol#L126](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L126) and please, take in consideration that this might add a reentrancy issue, so add the `nonReentrant` modifier. You are importing the `ReentrancyGuard` but not using this modifier

```diff
diff --git a/contracts/contracts/core/BufferBinaryOptions.sol b/contracts/contracts/core/BufferBinaryOptions.sol
index b93e6f0..efba433 100644
--- a/contracts/contracts/core/BufferBinaryOptions.sol
+++ b/contracts/contracts/core/BufferBinaryOptions.sol
@@ -107,7 +107,7 @@ contract BufferBinaryOptions is
     function createFromRouter(
         OptionParams calldata optionParams,
         bool isReferralValid
-    ) external override onlyRole(ROUTER_ROLE) returns (uint256 optionID) {
+    ) external override onlyRole(ROUTER_ROLE) nonReentrant() returns (uint256 optionID) {
         Option memory option = Option(
             State.Active,
             optionParams.strike,
@@ -123,7 +123,7 @@ contract BufferBinaryOptions is
         optionID = _generateTokenId();
         userOptionIds[optionParams.user].push(optionID);
         options[optionID] = option;
-        _mint(optionParams.user, optionID);
+        _safeMint(optionParams.user, optionID);
 
         uint256 referrerFee = _processReferralRebate(
             optionParams.user,
```