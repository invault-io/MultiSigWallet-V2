pragma solidity ^0.5.2;
import "./RLPEncode.sol";

/**
 * @title IVTPermission
 * @dev Contract for Permission applications.
 */
contract IVTPermission is RLPEncode {

    /// @dev  (签名地址==》标志位)
    mapping (address => bool) public signers;
    /// @dev  （交易历史==》标志位）
    mapping (uint256 => bool) public transactions;
    /// @dev  签名所需最少签名
    uint8 public required;

    /// @dev  Emitted by successful `upgrade` calls.
    event Completed(
        bytes4 _callbackSelector,
        address _newAddress,
        address _sender
    );

    constructor(address[] memory _signers, uint8 _required) public {
        require(_required <= _signers.length && _required > 0 && _signers.length > 0);

        for (uint8 i = 0; i < _signers.length; i++){
            require(_signers[i] != address(0));
            signers[_signers[i]] = true;
        }
        required = _required;
    }

    /**
     * @dev    外部函数，升级确认
     * @param  _callbackSelector 回调函数选择器
     * @param  _newAddress 新的地址
     * @param  _strTransactionData v4版本数据结构 [proxy地址]+[时间戳]
     * @param  _v v数组，如[27,28,28]
     * @param  _r r数组，如["","",""]
     * @param  _s s数组，如["","",""]
     * @return
     */
    function confirmChange(bytes4 _callbackSelector, address _newAddress, string memory _strTransactionData, uint8[] memory _v, bytes32[] memory _r, bytes32[] memory _s) public {
        processAndCheckParam(_newAddress, _strTransactionData, _v, _r, _s);
        _strTransactionData = RLPEncode.strConcat(_strTransactionData, RLPEncode.fromCode(_callbackSelector));
        //value 使用固定值03e8
        bytes32 _msgHash = getMsgHash(_newAddress, "03e8", _strTransactionData);

        verifySignatures(_msgHash, _v, _r, _s);

        msg.sender.call(abi.encodeWithSelector(_callbackSelector, _newAddress));
        emit Completed(_callbackSelector, _newAddress, msg.sender);
    }


    /**
     * @dev    校验参数，内部函数
     * @param  _destination 升级新地址
     * @param  _strTransactionData 签名数据，v4版本数据结构为 [proxy地址]+[时间戳]
     * @param  _v 如上
     * @param  _r 如上
     * @param  _s 如上
     * @return
     */
    function processAndCheckParam(address _destination, string memory _strTransactionData, uint8[] memory _v, bytes32[] memory _r, bytes32[] memory _s)  internal {
        require(_destination != address(0)  && _v.length == _r.length && _v.length == _s.length && _v.length > 0);

        string memory strTransactionTime = RLPEncode.subString(_strTransactionData, 40, 48);
        uint256 transactionTime = RLPEncode.stringToUint(strTransactionTime);
        require(!transactions[transactionTime]);

        string memory strTransactionAddress = RLPEncode.subString(_strTransactionData, 0, 40);
        address contractAddress = RLPEncode.stringToAddr(strTransactionAddress);
        //多签地址 == proxy地址
        require(contractAddress == address(msg.sender));

        transactions[transactionTime] = true;
    }


    /**
     * @dev   内部函数，校验签名
     * @param _msgHash 签名消息Hash
     * @param  _v  如上
     * @param  _r  如上
     * @param  _s  如上
     * @return
     */
    function verifySignatures(bytes32 _msgHash, uint8[] memory _v, bytes32[] memory _r,bytes32[] memory _s) view internal {
        uint8 hasConfirmed = 0;
        address[] memory  tempAddresses = new address[](_v.length);

        for (uint8 i = 0; i < _v.length; i++){
            tempAddresses[i]  = ecrecover(_msgHash, _v[i], _r[i], _s[i]);

            require(signers[tempAddresses[i]]);
            hasConfirmed++;
        }

        for (uint8 m = 0; m < _v.length; m++){
            for (uint8 n = m + 1; n< _v.length; n++){
                require(tempAddresses[m] != tempAddresses[n]);
            }
        }

        require(hasConfirmed >= required);
    }

}