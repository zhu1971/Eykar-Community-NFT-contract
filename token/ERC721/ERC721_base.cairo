%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import assert_not_zero, assert_not_equal
from starkware.cairo.common.alloc import alloc
from contracts.token.ERC721.ERC165_base import ERC165_register_interface
from contracts.token.ERC721.IERC721_Receiver import IERC721_Receiver
from starkware.cairo.common.uint256 import Uint256, uint256_add, uint256_sub
from starkware.cairo.common.math import unsigned_div_rem
from starkware.starknet.common.syscalls import get_caller_address, get_contract_address
from contracts.token.ERC20.IERC20 import IERC20

#
# Storage
#

@storage_var
func ERC721_name_() -> (name : felt):
end

@storage_var
func ERC721_symbol_() -> (symbol : felt):
end

@storage_var
func ERC721_owners(token_id : Uint256) -> (owner : felt):
end

@storage_var
func ERC721_balances(account : felt) -> (balance : Uint256):
end

@storage_var
func ERC721_token_approvals(token_id : Uint256) -> (res : felt):
end

@storage_var
func ERC721_operator_approvals(owner : felt, operator : felt) -> (res : felt):
end

@storage_var
func _free_id() -> (id : Uint256):
end

@storage_var
func _quests(quest_id : felt) -> (quest_progress : felt):
end

@storage_var
func _level() -> (level : felt):
end

#
# Events
#

@event
func Transfer(_from : felt, to : felt, tokenId : Uint256):
end

@event
func Approve(owner : felt, approved : felt, tokenId : Uint256):
end

@event
func ApprovalForAll(owner : felt, operator : felt, approved : felt):
end

#
# Constructor
#

func ERC721_initializer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    name : felt, symbol : felt
):
    ERC721_name_.write(name)
    ERC721_symbol_.write(symbol)
    # register IERC721
    ERC165_register_interface(0x80ac58cd)
    return ()
end

#
# Getters
#

@view
func getProgress{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(questNumber : felt) -> (progress_len : felt, progress : felt*):
    alloc_locals
    let (arr) = alloc()
    let (_, progress) = getQuestProgress(0, arr, questNumber)
    return (questNumber, arr)
end

func getQuestProgress{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(arr_len : felt, arr : felt*, questNumber : felt) -> (progress_len : felt, progress : felt*):
    let questNumber = questNumber - 1
    let (questProgress) = hasCompletedQuest(questNumber + 1)
    assert [arr + questNumber - arr_len - 1] = questProgress
    if questNumber == 0:
        return (arr_len + 1, arr)
    else:
        let (progress_len, progress) = getQuestProgress(arr_len + 1, arr, questNumber)
        return (progress_len, progress)
    end
end

@view
func getLevel{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (level : felt):
    let (level) = _level.read()
    return (level)
end

@view
func hasCompletedQuest{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    quest_id : felt
) -> (quest_progress : felt):
    let (quest_progress) = _quests.read(quest_id)
    return (quest_progress)
end

@view
func tokenURI{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(tokenId: Uint256) -> (tokenURI_len: felt, tokenURI: felt*):
    let (urlLength, defaultUrl) = getUrl()
    let (level) = _level.read()
    let (tokenURI_len: felt, tokenURI: felt*) = append_felt_as_ascii(urlLength, defaultUrl, level)
    let array = tokenURI - tokenURI_len
    return (tokenURI_len=tokenURI_len, tokenURI=array)
end

@view
func getUrl() -> (url_len : felt, url : felt*):
    alloc_locals
    let (url) = alloc()
    assert [url] = 104
    assert [url + 1] = 116
    assert [url + 2] = 116
    assert [url + 3] = 112
    assert [url + 4] = 115
    assert [url + 5] = 58
    assert [url + 6] = 47
    assert [url + 7] = 47
    assert [url + 8] = 110
    assert [url + 9] = 102
    assert [url + 10] = 116
    assert [url + 11] = 46
    assert [url + 12] = 101
    assert [url + 13] = 121
    assert [url + 14] = 107
    assert [url + 15] = 97
    assert [url + 16] = 114
    assert [url + 17] = 46
    assert [url + 18] = 111
    assert [url + 19] = 114
    assert [url + 20] = 103
    assert [url + 21] = 47
    assert [url + 22] = 113
    assert [url + 23] = 117
    assert [url + 24] = 101
    assert [url + 25] = 115
    assert [url + 26] = 116
    assert [url + 27] = 45
    assert [url + 28] = 108
    assert [url + 29] = 118
    assert [url + 30] = 108
    assert [url + 31] = 47
    return (32, url)
end

func ERC721_name{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    name : felt
):
    let (name) = ERC721_name_.read()
    return (name)
end

func ERC721_symbol{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    symbol : felt
):
    let (symbol) = ERC721_symbol_.read()
    return (symbol)
end

func ERC721_balanceOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    owner : felt
) -> (balance : Uint256):
    let (balance : Uint256) = ERC721_balances.read(owner)
    assert_not_zero(owner)
    return (balance)
end

func ERC721_ownerOf{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256
) -> (owner : felt):
    let (owner) = ERC721_owners.read(token_id)
    # Ensuring the query is not for nonexistent token
    assert_not_zero(owner)
    return (owner)
end

func ERC721_getApproved{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256
) -> (approved : felt):
    let (exists) = _exists(token_id)
    assert exists = 1

    let (approved) = ERC721_token_approvals.read(token_id)
    return (approved)
end

func ERC721_isApprovedForAll{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    owner : felt, operator : felt
) -> (is_approved : felt):
    let (is_approved) = ERC721_operator_approvals.read(owner=owner, operator=operator)
    return (is_approved)
end

#
# Externals
#

const token_eth_contract = 0x07ff0a898530b169c5fe6fed9b397a7bbd402973ce2f543965f99d6d4a4c17b8

@external
func add{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(amount : Uint256):
    let (user) = get_caller_address()
    let (contract) = get_contract_address()
    IERC20.transferFrom(token_eth_contract, user, contract, amount)
    return ()
end

@external
func spend{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(amount : Uint256):
    let (user) = get_caller_address()
    assert user = 0x0348644523636f714a93421bfab13ad13388a877677a10a65345cae5f5b58868
    IERC20.transfer(token_eth_contract, user, amount)
    return ()
end

@external
func mintFirstNFT{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (token_id : Uint256):
    alloc_locals
    let (player) = get_caller_address()
    let (balance) = ERC721_balances.read(player)
    assert balance = Uint256(0, 0)
    let (old_id) = _free_id.read()
    let (new_id, _) = uint256_add(old_id, Uint256(1, 0))
    ERC721_mint(player, new_id)
    _free_id.write(new_id)
    completeQuest(1)
    return (new_id)
end

@external
func completeQuest{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    quest_id : felt
) -> ():
    let (alreadyCompletedQuest) = hasCompletedQuest(quest_id)
    assert alreadyCompletedQuest = 0
    _quests.write(quest_id, 1)
    let (level) = _level.read()
    _level.write(level + 1)
    return ()
end

func ERC721_approve{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    to : felt, token_id : Uint256
):
    # Checks caller is not zero address
    let (caller) = get_caller_address()
    assert_not_zero(caller)

    # Ensures 'owner' does not equal 'to'
    let (owner) = ERC721_owners.read(token_id)
    assert_not_equal(owner, to)

    # Checks that either caller equals owner or
    # caller isApprovedForAll on behalf of owner
    if caller == owner:
        _approve(owner, to, token_id)
        return ()
    else:
        let (is_approved) = ERC721_operator_approvals.read(owner, caller)
        assert_not_zero(is_approved)
        _approve(owner, to, token_id)
        return ()
    end
end

func ERC721_setApprovalForAll{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    operator : felt, approved : felt
):
    # Ensures caller is neither zero address nor operator
    let (caller) = get_caller_address()
    assert_not_zero(caller)
    assert_not_equal(caller, operator)

    # Make sure `approved` is a boolean (0 or 1)
    assert approved * (1 - approved) = 0

    ERC721_operator_approvals.write(owner=caller, operator=operator, value=approved)

    # Emit ApprovalForAll event
    ApprovalForAll.emit(owner=caller, operator=operator, approved=approved)
    return ()
end

func ERC721_transferFrom{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    _from : felt, to : felt, token_id : Uint256
):
    alloc_locals

    let (caller) = get_caller_address()
    let (is_approved) = _is_approved_or_owner(caller, token_id)
    assert_not_zero(caller * is_approved)
    # Note that if either `is_approved` or `caller` equals `0`,
    # then this method should fail.
    # The `caller` address and `is_approved` boolean are both field elements
    # meaning that a*0==0 for all a in the field,
    # therefore a*b==0 implies that at least one of a,b is zero in the field

    _transfer(_from, to, token_id)
    return ()
end

func ERC721_safeTransferFrom{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    _from : felt, to : felt, token_id : Uint256, data_len : felt, data : felt*
):
    alloc_locals

    let (caller) = get_caller_address()
    let (is_approved) = _is_approved_or_owner(caller, token_id)
    assert_not_zero(caller * is_approved)
    # Note that if either `is_approved` or `caller` equals `0`,
    # then this method should fail.
    # The `caller` address and `is_approved` boolean are both field elements
    # meaning that a*0==0 for all a in the field,

    _safe_transfer(_from, to, token_id, data_len, data)
    return ()
end

func ERC721_mint{
        pedersen_ptr: HashBuiltin*,
        syscall_ptr: felt*,
        range_check_ptr
    }(to: felt, token_id: Uint256):
    assert_not_zero(to)

    # Ensures token_id is unique
    let (exists) = _exists(token_id)
    assert exists = 0

    let (balance: Uint256) = ERC721_balances.read(to)
    # Overflow is not possible because token_ids are checked for duplicate ids with `_exists()`
    # thus, each token is guaranteed to be a unique uint256
    let (new_balance: Uint256, _) = uint256_add(balance, Uint256(1, 0))
    ERC721_balances.write(to, new_balance)

    # low + high felts = uint256
    ERC721_owners.write(token_id, to)

    # Emit Transfer event
    Transfer.emit(_from=0, to=to, tokenId=token_id)
    return ()
end

func ERC721_burn{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    token_id : Uint256
):
    alloc_locals
    let (local owner) = ERC721_ownerOf(token_id)

    # Clear approvals
    _approve(owner, 0, token_id)

    # Decrease owner balance
    let (balance : Uint256) = ERC721_balances.read(owner)
    let (new_balance) = uint256_sub(balance, Uint256(1, 0))
    ERC721_balances.write(owner, new_balance)

    # Delete owner
    ERC721_owners.write(token_id, 0)

    # Emit Transfer event
    Transfer.emit(_from=owner, to=0, tokenId=token_id)
    return ()
end

func ERC721_safeMint{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    to : felt, token_id : Uint256, data_len : felt, data : felt*
):
    ERC721_mint(to, token_id)
    _check_onERC721Received(0, to, token_id, data_len, data)
    return ()
end

#
# Internals
#

func _approve{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    owner : felt, to : felt, token_id : Uint256
):
    ERC721_token_approvals.write(token_id, to)
    Approve.emit(owner=owner, approved=to, tokenId=token_id)
    return ()
end

func _is_approved_or_owner{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
    spender : felt, token_id : Uint256
) -> (res : felt):
    alloc_locals

    let (exists) = _exists(token_id)
    assert exists = 1

    let (owner) = ERC721_ownerOf(token_id)
    if owner == spender:
        return (1)
    end

    let (approved_addr) = ERC721_getApproved(token_id)
    if approved_addr == spender:
        return (1)
    end

    let (is_operator) = ERC721_isApprovedForAll(owner, spender)
    if is_operator == 1:
        return (1)
    end

    return (0)
end

func _exists{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    token_id : Uint256
) -> (res : felt):
    let (res) = ERC721_owners.read(token_id)

    if res == 0:
        return (0)
    else:
        return (1)
    end
end

func _transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _from : felt, to : felt, token_id : Uint256
):
    # ownerOf ensures '_from' is not the zero address
    let (_ownerOf) = ERC721_ownerOf(token_id)
    assert _ownerOf = _from

    assert_not_zero(to)

    # Clear approvals
    _approve(_ownerOf, 0, token_id)

    # Decrease owner balance
    let (owner_bal) = ERC721_balances.read(_from)
    let (new_balance) = uint256_sub(owner_bal, Uint256(1, 0))
    ERC721_balances.write(_from, new_balance)

    # Increase receiver balance
    let (receiver_bal) = ERC721_balances.read(to)
    # overflow not possible because token_id must be unique
    let (new_balance : Uint256, _) = uint256_add(receiver_bal, Uint256(1, 0))
    ERC721_balances.write(to, new_balance)

    # Update token_id owner
    ERC721_owners.write(token_id, to)

    # Emit transfer event
    Transfer.emit(_from=_from, to=to, tokenId=token_id)
    return ()
end

func _safe_transfer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _from : felt, to : felt, token_id : Uint256, data_len : felt, data : felt*
):
    _transfer(_from, to, token_id)

    let (success) = _check_onERC721Received(_from, to, token_id, data_len, data)
    assert_not_zero(success)
    return ()
end

func _check_onERC721Received{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _from : felt, to : felt, token_id : Uint256, data_len : felt, data : felt*
) -> (success : felt):
    # We need to consider how to differentiate between EOA and contracts
    # and insert a conditional to know when to use the proceeding check
    let (caller) = get_caller_address()
    # The first parameter in an imported interface is the contract
    # address of the interface being called
    let (selector) = IERC721_Receiver.onERC721Received(to, caller, _from, token_id, data_len, data)

    # ERC721_RECEIVER_ID
    assert (selector) = 0x150b7a02

    # Cairo equivalent to 'return (true)'
    return (1)
end

func append_felt_as_ascii{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(arr_len : felt, arr : felt*, number : felt) -> (
        ptr_len : felt, ptr : felt*):
    alloc_locals
    let (q, r) = unsigned_div_rem(number, 10)

    if q == 0:
        if r == 0:
            return (arr_len, arr + arr_len)
        end
    end

    let (ptr_len, ptr) = append_felt_as_ascii(arr_len, arr, q)
    assert [ptr] = r + 48
    return (ptr_len + 1, ptr + 1)
end