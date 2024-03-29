
  [![NPM Version](https://img.shields.io/npm/v/@futoin/security.svg?style=flat)](https://www.npmjs.com/package/@futoin/security)
  [![NPM Downloads](https://img.shields.io/npm/dm/@futoin/security.svg?style=flat)](https://www.npmjs.com/package/@futoin/security)
  [![Build Status](https://travis-ci.org/futoin/core-js-ri-security.svg)](https://travis-ci.org/futoin/core-js-ri-security)
  [![stable](https://img.shields.io/badge/stability-stable-green.svg?style=flat)](https://www.npmjs.com/package/@futoin/security)

  [![NPM](https://nodei.co/npm/@futoin/security.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/@futoin/security/)

# About

FutoIn Security Concept is alternative to token based authentication & authorization mechanisms.

Features:

* [FutoIn SecVault](https://github.com/futoin/core-js-ri-secvault) sensitive data storage security
* User & configuration management (FTN8):
* Stateless Authentication (FTN8.1):
    - Clear text
    - Message Authentication Code (HMAC with static key)
* Master Secret Authentication (FTN8.2):
    - multiple master keys with custom scope support
    - derived key per each peer
    - automatic time-based derived key rotation
    - optional automatic master key rotation

**Documentation** --> [FutoIn Guide](https://futoin.org/docs/)

Reference implementation of:
 
* [FTN8: FutoIn Security Concept](https://specs.futoin.org/draft/preview/ftn8_security_concept.html)
* [FTN8.1: Stateless Authentication](https://specs.futoin.org/draft/preview/ftn8.1_stateless_auth.html)
* [FTN8.2: Master Secret Authentication](https://specs.futoin.org/draft/preview/ftn8.2_master_auth.html)

Author: [Andrey Galkin](mailto:andrey@futoin.org)

# Installation for Node.js

Command line:
```sh
$ npm install @futoin/security --save
```
or:

```sh
$ yarn add @futoin/security --save
```

# Examples

```javascript
```
    
# API documentation

## Classes

<dl>
<dt><a href="#CachedManageService">CachedManageService</a></dt>
<dd><p>FTN8: Cached Manage Service</p>
</dd>
<dt><a href="#ManageFace">ManageFace</a></dt>
<dd><p>Manage Face</p>
</dd>
<dt><a href="#ManageService">ManageService</a></dt>
<dd><p>FTN8: main Manage Service</p>
</dd>
<dt><a href="#MasterAutoregFace">MasterAutoregFace</a></dt>
<dd><p>FTN8.2: Master Auth Face</p>
</dd>
<dt><a href="#MasterAuthService">MasterAuthService</a></dt>
<dd><p>FTN8.2: Master Auth Service</p>
</dd>
<dt><a href="#MasterAutoregFace">MasterAutoregFace</a></dt>
<dd><p>FTN8.2: Master Auth Auto-registration Face</p>
</dd>
<dt><a href="#MasterAutoregService">MasterAutoregService</a></dt>
<dd><p>FTN8.2: Master Auth Auto-registration Service</p>
</dd>
<dt><a href="#MasterManageFace">MasterManageFace</a></dt>
<dd><p>FTN8.2: Master Auth Manage Face</p>
</dd>
<dt><a href="#MasterManageService">MasterManageService</a></dt>
<dd><p>FTN8.2: Master Auth Manage Service</p>
</dd>
<dt><a href="#ServiceApp">ServiceApp</a></dt>
<dd><p>All-in-one AuthService initialization</p>
</dd>
<dt><a href="#SimpleSecurityProvider">SimpleSecurityProvider</a></dt>
<dd><p>Simple passthru FTN8 security provider for Executor.</p>
<p>NOTE: it&#39;s suitable for lightweight services without own SecVault.</p>
</dd>
<dt><a href="#SatelessAuthFace">SatelessAuthFace</a></dt>
<dd><p>FTN8.1: Stateless AuthService Face</p>
</dd>
<dt><a href="#StatelessAuthService">StatelessAuthService</a></dt>
<dd><p>Manage Service</p>
</dd>
<dt><a href="#StatelessManageFace">StatelessManageFace</a></dt>
<dd><p>FTN8.1: Stateless Manage Face</p>
</dd>
<dt><a href="#StatelessManageService">StatelessManageService</a></dt>
<dd><p>FTN8.1.: Stateless Manage Service</p>
</dd>
<dt><a href="#StaticMasterAuth">StaticMasterAuth</a></dt>
<dd><p>MasterAuth implementation for AdvancedCCM with static Master Key</p>
<p>NOTE: this implementation rotates only derived keys</p>
</dd>
<dt><a href="#BaseFace">BaseFace</a></dt>
<dd><p>Base Face with neutral common registration functionality</p>
</dd>
<dt><a href="#BaseService">BaseService</a></dt>
<dd><p>Base Service with common registration logic</p>
</dd>
</dl>

<a name="CachedManageService"></a>

## CachedManageService
FTN8: Cached Manage Service

**Kind**: global class  
<a name="new_CachedManageService_new"></a>

### new CachedManageService(scope, options)
C-tor


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| scope | <code>object</code> |  | scope of related services |
| options | <code>object</code> |  | passed to superclass c-tor |
| options.scope | <code>integer</code> | <code>main.globalScope</code> | scope state |

<a name="ManageFace"></a>

## ManageFace
Manage Face

**Kind**: global class  
<a name="ManageService"></a>

## ManageService
FTN8: main Manage Service

**Kind**: global class  
<a name="MasterAutoregFace"></a>

## MasterAutoregFace
FTN8.2: Master Auth Face

**Kind**: global class  
<a name="MasterAuthService"></a>

## MasterAuthService
FTN8.2: Master Auth Service

**Kind**: global class  
<a name="MasterAutoregFace"></a>

## MasterAutoregFace
FTN8.2: Master Auth Auto-registration Face

**Kind**: global class  
<a name="MasterAutoregService"></a>

## MasterAutoregService
FTN8.2: Master Auth Auto-registration Service

**Kind**: global class  
<a name="MasterManageFace"></a>

## MasterManageFace
FTN8.2: Master Auth Manage Face

**Kind**: global class  
<a name="MasterManageService"></a>

## MasterManageService
FTN8.2: Master Auth Manage Service

**Kind**: global class  
<a name="ServiceApp"></a>

## ServiceApp
All-in-one AuthService initialization

**Kind**: global class  

* [ServiceApp](#ServiceApp)
    * [new ServiceApp(as, options)](#new_ServiceApp_new)
    * [.ccm()](#ServiceApp+ccm) ⇒ <code>AdvancedCCM</code>
    * [.executor()](#ServiceApp+executor) ⇒ <code>Executor</code>
    * [.close([done])](#ServiceApp+close)

<a name="new_ServiceApp_new"></a>

### new ServiceApp(as, options)
C-tor


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| as | <code>AsyncSteps</code> |  | AsyncSteps interface |
| options | <code>object</code> | <code>{}</code> | options |
| [options.ccm] | <code>AdvancedCCM</code> |  | external CCM instance |
| [options.publicExecutor] | <code>Executor</code> |  | external public executor instance |
| [options.privateExecutor] | <code>Executor</code> |  | external private executor instance |
| [options.storagePassword] | <code>string</code> |  | Base64 encoded KEK for storage |
| [options.config] | <code>object</code> |  | config overrides for MasterService |
| [options.ccmOptions] | <code>object</code> |  | auto-CCM options |
| [options.notExpectedHandler] | <code>callable</code> |  | 'notExpected' error handler |
| [options.privateExecutorOptions] | <code>object</code> |  | private auto-Executor options |
| [options.publicExecutorOptions] | <code>object</code> |  | public auto-Executor options |
| [options.evtOptions] | <code>object</code> |  | eventstream options |
| [options.secVaultOptions] | <code>object</code> |  | secure vault options |
| [options.securityOptions] | <code>object</code> |  | security interface options |

<a name="ServiceApp+ccm"></a>

### serviceApp.ccm() ⇒ <code>AdvancedCCM</code>
CCM instance accessor

**Kind**: instance method of [<code>ServiceApp</code>](#ServiceApp)  
**Returns**: <code>AdvancedCCM</code> - instance  
<a name="ServiceApp+executor"></a>

### serviceApp.executor() ⇒ <code>Executor</code>
Executor instance accessor

**Kind**: instance method of [<code>ServiceApp</code>](#ServiceApp)  
**Returns**: <code>Executor</code> - instance  
<a name="ServiceApp+close"></a>

### serviceApp.close([done])
Shutdown of app and related instances

**Kind**: instance method of [<code>ServiceApp</code>](#ServiceApp)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [done] | <code>callable</code> | <code></code> | done callback |

<a name="SimpleSecurityProvider"></a>

## SimpleSecurityProvider
Simple passthru FTN8 security provider for Executor.

NOTE: it's suitable for lightweight services without own SecVault.

**Kind**: global class  
<a name="SatelessAuthFace"></a>

## SatelessAuthFace
FTN8.1: Stateless AuthService Face

**Kind**: global class  
<a name="StatelessAuthService"></a>

## StatelessAuthService
Manage Service

**Kind**: global class  
<a name="StatelessManageFace"></a>

## StatelessManageFace
FTN8.1: Stateless Manage Face

**Kind**: global class  
<a name="StatelessManageService"></a>

## StatelessManageService
FTN8.1.: Stateless Manage Service

**Kind**: global class  
<a name="StaticMasterAuth"></a>

## StaticMasterAuth
MasterAuth implementation for AdvancedCCM with static Master Key

NOTE: this implementation rotates only derived keys

**Kind**: global class  
<a name="new_StaticMasterAuth_new"></a>

### new StaticMasterAuth(options, keyId, keyData, [paramFormat], [kds], [macAlgo])
C-tor


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| options | <code>object</code> |  | Options |
| keyId | <code>string</code> |  | master key ID |
| keyData | <code>string</code> |  | master key data in Base64 |
| [paramFormat] | <code>string</code> | <code>&quot;YYYYMMDD&quot;</code> | format for derivation parameter |
| [kds] | <code>string</code> | <code>&quot;HKDF256&quot;</code> | key derivation strategy |
| [macAlgo] | <code>string</code> | <code>&quot;HS256&quot;</code> | MAC algorithm |

<a name="BaseFace"></a>

## BaseFace
Base Face with neutral common registration functionality

**Kind**: global class  
**Note**: Not official API  

* [BaseFace](#BaseFace)
    * [.LATEST_VERSION](#BaseFace.LATEST_VERSION)
    * [.PING_VERSION](#BaseFace.PING_VERSION)
    * [.register(as, ccm, name, endpoint, [credentials], [options])](#BaseFace.register)

<a name="BaseFace.LATEST_VERSION"></a>

### BaseFace.LATEST\_VERSION
Latest supported FTN13 version

**Kind**: static property of [<code>BaseFace</code>](#BaseFace)  
<a name="BaseFace.PING_VERSION"></a>

### BaseFace.PING\_VERSION
Latest supported FTN4 version

**Kind**: static property of [<code>BaseFace</code>](#BaseFace)  
<a name="BaseFace.register"></a>

### BaseFace.register(as, ccm, name, endpoint, [credentials], [options])
CCM registration helper

**Kind**: static method of [<code>BaseFace</code>](#BaseFace)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| as | <code>AsyncSteps</code> |  | steps interface |
| ccm | <code>AdvancedCCM</code> |  | CCM instance |
| name | <code>string</code> |  | CCM registration name |
| endpoint | <code>\*</code> |  | see AdvancedCCM#register |
| [credentials] | <code>\*</code> | <code></code> | see AdvancedCCM#register |
| [options] | <code>object</code> | <code>{}</code> | interface options |
| [options.version] | <code>string</code> | <code>&quot;1.0&quot;</code> | interface version to use |

<a name="BaseService"></a>

## BaseService
Base Service with common registration logic

**Kind**: global class  

* [BaseService](#BaseService)
    * [new BaseService(scope, options)](#new_BaseService_new)
    * [.register(as, executor, scope, options)](#BaseService.register) ⇒ [<code>BaseService</code>](#BaseService)

<a name="new_BaseService_new"></a>

### new BaseService(scope, options)
C-tor


| Param | Type | Description |
| --- | --- | --- |
| scope | <code>object</code> | scope of related services |
| options | <code>object</code> | passed to superclass c-tor |

<a name="BaseService.register"></a>

### BaseService.register(as, executor, scope, options) ⇒ [<code>BaseService</code>](#BaseService)
Register Service with Executor

**Kind**: static method of [<code>BaseService</code>](#BaseService)  
**Returns**: [<code>BaseService</code>](#BaseService) - instance  

| Param | Type | Description |
| --- | --- | --- |
| as | <code>AsyncSteps</code> | steps interface |
| executor | <code>Executor</code> | executor instance |
| scope | <code>object</code> | scope of related services |
| options | <code>object</code> | implementation defined options |


