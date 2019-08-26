pragma solidity ^0.5.2;

import "./Pausable.sol";
import "./AddressUtils.sol";


/**
 * @title UpgradeabilityProxy
 * @dev This contract implements a proxy that allows to change the
 * implementation address to which it will delegate.
 * Such a change is called an implementation upgrade.
 */
contract UpgradeabilityProxy {
    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "www.invault.io.proxy.implementation", and is
     * validated in the constructor.
     */
    bytes32 private constant IMPLEMENTATION_SLOT = 0xbe2c1a60709d4c60c413b72a0999dd04a683092d060b4c9def249fa6bc842b2d;

    /**
     * @dev Contract constructor.
     * @param _implementation Address of the initial implementation.
     * It should include the signature and the parameters of the function to be called, as described in
     * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
     * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
     */
    constructor(address _implementation) public {
        assert(IMPLEMENTATION_SLOT == keccak256("www.invault.io.proxy.implementation"));
        _setImplementation(_implementation);
    }

    /**
     * @dev Returns the current implementation.
     * @return Address of the current implementation
     */
    function _implementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    /**
     * @dev Upgrades the proxy to a new implementation.
     * @param newImplementation Address of the new implementation.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
    }

    /**
     * @dev 设置proxy的Impl地址
     * @param newImplementation Address of the new implementation.
     */
    function _setImplementation(address newImplementation) private {
        require(AddressUtils.isContract(newImplementation), "Cannot set a proxy implementation to a non-contract address");

        bytes32 slot = IMPLEMENTATION_SLOT;

        assembly {
            sstore(slot, newImplementation)
        }
    }
}


/**
 * @title IVTProxy
 * @dev Contract for Proxy applications.
 */
contract IVTProxy is UpgradeabilityProxy, Pausable {

    /**
     * @dev Storage slot with the perm of the contract.
     * This is the keccak-256 hash of "www.invault.io.proxy.permission", and is
     * validated in the constructor.
     */
    bytes32 private constant PERM_SLOT = 0x9f2b05956adf3f5dc678f8c50dd9693f2163f4bec0d0b84a13327b894102a4e5;

    /**
     * @dev Modifier to check whether the `msg.sender` is the Permission.
     * If it is, it will run the function.
     */
    modifier OnlyPermission() {
        require(msg.sender == _perm());
        _;
    }

    /**
     * Contract constructor.
     * @param _implementation address of the initial implementation.
     * It should include the signature and the parameters of the function to be called, as described in
     * https://solidity.readthedocs.io/en/v0.4.24/abi-spec.html#function-selector-and-argument-encoding.
     * This parameter is optional, if no data is given the initialization call to proxied contract will be skipped.
     */
    constructor(address _implementation, address _permission) UpgradeabilityProxy(_implementation) public {
        assert(PERM_SLOT == keccak256("www.invault.io.proxy.permission"));
        _setPermission(_permission);
    }

    /**
     * @return The address of the proxy admin.
     */
    function getPermAddress() external view whenNotPaused returns (address) {
        return _perm();
    }

    /**
     * @return The address of the implementation.
     */
    function getImplAddress() external view whenNotPaused returns (address) {
        return _implementation();
    }

    /**
     * @dev 升级proxy中的implementation，只有Permission可以调用
     * @param newImplementation Address of the new implementation.
     */
    function upgradeImpl(address newImplementation) external OnlyPermission whenNotPaused returns(bool) {
        _upgradeTo(newImplementation);
        return true;
    }



    /**
     * @dev 升级proxy中的permission，只有Permission可以调用
     * @param newPermission Address.
     */
    function upgradePerm(address newPermission) external OnlyPermission whenNotPaused returns(bool)  {
        _setPermission(newPermission);
        return true;
    }


    /**
     * @dev 请求升级
     * @param _data call
     * @return {[type]}
     */
    function requestUpgrade(bytes calldata _data) external onlyOwner whenNotPaused {
        address permission = _perm();
        permission.call(_data);
    }

    /**
     * @return The permission slot.
     */
    function _perm() internal view returns (address adm) {
        bytes32 slot = PERM_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    /**
     * @dev Sets the address of the proxy permission.
     * @param newPerm Address of the new proxy permission.
     */
    function _setPermission(address newPerm) internal {

        require(AddressUtils.isContract(newPerm), "Cannot set a proxy permission to a non-contract address");

        bytes32 slot = PERM_SLOT;

        assembly {
            sstore(slot, newPerm)
        }
    }

}


