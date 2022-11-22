dipp

medium

# Insufficient support for fee-on-transfer tokens

## Summary

The ```BufferBinaryPool.sol``` and ```BufferRouter.sol``` do not support fee-on-transfer tokens. If ```tokenX``` is a fee-on-transfer token, tokens received from users could be less than the amount specified in the transfer.

## Vulnerability Detail

The ```initiateTrade``` function in ```BufferRouter.sol``` receives tokens from the user with amount set to ```initiateTrade```'s ```totalFee``` input. If tokenX is a fee-on-transfer token then the actual amount received by ```BufferRouter.sol``` is less than ```totalFee```. When a trade is opened, the protocol will [send a settlementFee to ```settlementFeeDisbursalContract```](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L137-L141) and a [premium to ```BufferBinaryPool.sol```](), where the settlementFee is calculated using the incorrect, inflated totalFee amount. When the totalFee is greater than the fee required [the user is reimbursed the difference](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L333-L339). Since the settlementFee is greater than it should be the user receives less reimbursement.

In ```BufferBinaryPool.sol```'s ```lock``` function, the premium for the order is sent from the Options contract to the Pool. The totalPremium state variable would be updated incorrectly if fee-on-transfer tokens were used.

The ```_provide``` function in ```BufferBinaryPool.sol```receives tokenXAmount of tokenX tokens from the user and calculates the amount of shares to mint using the tokenXAmount. If fee-on-transfer tokens are used then the user would receive more shares than they should.

## Impact

The protocol and users could suffer a loss of funds.

## Code Snippet

[BufferRouter.sol#L86-L90](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferRouter.sol#L86-L90)

[BufferBinaryPool.sol#L161](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L161)

[BufferBinaryPool.sol#L236-L240](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L161)

## Tool used

Manual Review

## Recommendation

Consider checking the balance of the contract before and after token transfers and using instead of the amount specified in the contract.