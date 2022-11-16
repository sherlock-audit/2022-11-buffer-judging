rvierdiiev

medium

# BufferBinaryOptions.createFromRouter do not use safeMint

## Summary
Because `BufferBinaryOptions.createFromRouter` do not use safeMint it's possible to mint NFT to the contract the doesn't support ERC721. As result contract will not be able to use ERC721 function to manage the token(like allowance, transfer). 
## Vulnerability Detail
`BufferBinaryOptions.createFromRouter` mints option token for trader in [not safe](https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L126) way. Though even if option creator is contract that doesn't support ERC721, it will be possible for him to win option as no need for option owner to do anything. But another things such transfer, allowance will be not available for the option owner.
## Impact
Option owner is not able to use ERC721 functions, so he can't resell option.
## Code Snippet
https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryOptions.sol#L126
## Tool used

Manual Review

## Recommendation
Use safeMint function when minting new token.