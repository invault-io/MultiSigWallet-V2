pragma solidity ^0.5.2;
import "./RLPEncode.sol";

/**
 * @title IVTImplementation
 * @dev Contract for Implementation applications.
 */
contract IVTImplementation is RLPEncode {
    event Transacted(address _to, address _tokenContractAddress, uint256 _value);
    event Errorlog(uint256 _type, string  _msg);

    /**
     * @dev    ETH转账逻辑处理， 外部函数
     * @param  _destination 最终转账目标地址
     * @param  _value 最终转账金额，如"03e8"
     * @param  _strTransactionData 签名数据，v4版本数据结构 [User地址]+[时间戳]
     * @param  _v v数组，如[27,28,28]
     * @param  _r r数组，如["","",""]
     * @param  _s s数组，如["","",""]
     * @return {[type]}
     */
    function submitTransaction(address payable _destination, string memory _value, string memory _strTransactionData, uint8[] memory _v, bytes32[] memory _r, bytes32[] memory _s)  public {
        IVTUserInterface userTemp = IVTUserInterface(address(this));

        processAndCheckParam(_destination, _strTransactionData, _v, _r, _s, userTemp);

        uint256 transactionValue = RLPEncode.stringToUint(_value);
        bytes32 _msgHash = getMsgHash(_destination, _value, _strTransactionData);
        verifySignatures(userTemp, _msgHash, _v, _r, _s);

        _destination.transfer(transactionValue); //此时的上下文仍为user合约

        emit Transacted(_destination, address(0), transactionValue);
    }

    /**
     * @dev Token转账逻辑处理
     * @param _destination 最终转账目标地址
     * @param  _tokenAddress  Token合约地址
     * @param  _value 最终转账金额，如"03e8"
     * @param  _strTransactionData 签名数据，v4版本数据结构 [User地址]+[时间戳]
     * @param  _v v数组，如[27,28,28]
     * @param  _r r数组，如["","",""]
     * @param  _s s数组，如["","",""]
     * @param  _tokenType Token版本，v4使用两种规范
     * @return {[type]}
     */
    function submitTransactionToken(address _destination, address _tokenAddress, string memory _value, string memory _strTransactionData, uint8[] memory _v, bytes32[] memory _r,bytes32[] memory _s, uint256  _tokenType)  public {
        IVTUserInterface userTemp = IVTUserInterface(address(this));

        processAndCheckParam(_destination, _strTransactionData, _v, _r, _s, userTemp);

        uint256 transactionValue = RLPEncode.stringToUint(_value);
        _strTransactionData = RLPEncode.strConcat(_strTransactionData, RLPEncode.addressToString(_tokenAddress));
        bytes32 _msgHash = getMsgHash(_destination, _value, _strTransactionData);
        verifySignatures(userTemp, _msgHash, _v, _r, _s);

        //此时的上下文仍为user合约--enum update to uint8 param by shitao. 10001 is ERC20_STANDARD ,10002 is ERC20_NONSTANDARD;
        if(10001 == _tokenType){
            ERC20StandardInterface instanceStandard = ERC20StandardInterface(_tokenAddress);
            require(instanceStandard.transfer(_destination, transactionValue));
        }else if(10002 == _tokenType){
            ERC20NonStandardInterface instanceNonStandard = ERC20NonStandardInterface(_tokenAddress);
            instanceNonStandard.transfer(_destination, transactionValue);
        }else{
            emit Errorlog(_tokenType, "unknownType");
        }

        emit Transacted(_tokenAddress , _destination, transactionValue);
    }

    /**
     * @dev    校验参数，内部函数
     * @param  _destination 最终转账目标地址
     * @param  _strTransactionData 签名数据，v4版本数据结构为 [user合约地址]+[时间戳]
     * @param  _v 如上
     * @param  _r 如上
     * @param  _s 如上
     * @return
     */
    function processAndCheckParam(address _destination, string memory _strTransactionData, uint8[] memory _v, bytes32[] memory _r, bytes32[] memory _s, IVTUserInterface _userTemp) internal {
        require(_destination != address(0)  && _v.length == _r.length && _v.length == _s.length && _v.length > 0);

        string memory strTransactionId = RLPEncode.subString(_strTransactionData, 40, 48);
        uint256 transactionId = RLPEncode.stringToUint(strTransactionId);
        require(!_userTemp.hasTransactionId(transactionId));


        string memory strTransactionAddress = RLPEncode.subString(_strTransactionData, 0, 40);
        address contractAddress = RLPEncode.stringToAddr(strTransactionAddress);

        //多签地址 == user地址
        require(contractAddress == address(_userTemp));

        _userTemp.setTransactionId(transactionId);
    }

    /**
     * @dev   内部函数，校验签名
     * @param _msgHash 签名消息Hash
     * @param  _v  如上
     * @param  _r  如上
     * @param  _s  如上
     * @return
     */
    function verifySignatures(IVTUserInterface _userTemp, bytes32 _msgHash, uint8[] memory _v, bytes32[] memory _r,bytes32[] memory _s) view internal {
        uint8 hasConfirmed = 0;
        address[] memory tempAddresses = new address[](_v.length);

        for (uint8 i = 0; i < _v.length; i++){
            tempAddresses[i] = ecrecover(_msgHash, _v[i], _r[i], _s[i]);

            require(_userTemp.hasSigner(tempAddresses[i]));
            hasConfirmed++;
        }


        for (uint8 m = 0; m < _v.length; m++){
            for (uint8 n = m + 1; n< _v.length; n++){
                require(tempAddresses[m] != tempAddresses[n]);
            }
        }
        require(hasConfirmed >= _userTemp.getRequired());
    }
}



contract ERC20StandardInterface {
    function transfer(address _to, uint256 _value) public returns (bool success);
}

contract ERC20NonStandardInterface {
    function transfer(address _to, uint256 _value) public;
}

contract IVTUserInterface {
    function setTransactionId(uint256 _time) public;
    function getRequired() public view returns (uint256);
    function hasSigner(address _signer)public view returns(bool);
    function hasTransactionId(uint256 _transactionId)public view returns(bool);
}