# Wingpy: Cisco APIs for Humans

__wingpy__ is an elegant and simple Cisco API library for Python, built for network engineers by [Wingmen Solutions](https://www.wingmen.dk/en/home-page/).

All Cisco APIs differ in how they handle authentication, session management, rate limiting, path construction, pagination and concurrency. With __wingpy__ you don't need to worry about all of the complexities associated with this.

Although many Cisco platforms have dedicated SDKs, each of them is designed and maintained individually and have notable differences. With __wingpy__, just start coding and interact directly with API endpoints! This makes it much easier to work with new Cisco platform APIs and automate across domains.

Plenty of examples and explanations are available in the [User Guide](https://wingpy.automation.wingmen.dk/user-guide)

## Features

- Session maintenance
- Rate limit handling
- Authentication
- Path building
- Concurrency
- Fully typed
- Pagination
- Headers

## Installation

### Install via uv

```bash
uv add wingpy
```

### Install via pip

```bash
pip install wingpy
```

### Install via poetry

```bash
poetry add wingpy
```

## Supported APIs

- Cisco APIC (Application Centric Infrastructure / ACI)
  
  ```python
  from wingpy import CiscoAPIC
  ```

- Cisco Catalyst Center
  
  ```python
  from wingpy import CiscoCatalystCenter
  ```

- Cisco FMC (Secure Firewall Management Center)
  
  ```python
  from wingpy import CiscoFMC
  ```

- Cisco Hyperfabric
  
  ```python
  from wingpy import CiscoHyperfabric
  ```

- Cisco ISE (Identity Service Engine)
  
  ```python
  from wingpy import CiscoISE
  ```

- Cisco Meraki Dashboard
  
  ```python
  from wingpy import CiscoMerakiDashboard
  ```

- Cisco Nexus Dashboard
  
  ```python
  from wingpy import CiscoNexusDashboard
  ```

## Configuration

The recommended way to specify API authentication parameters is through environment variables:

- `WINGPY_*_BASE_URL`
- `WINGPY_*_USERNAME`
- `WINGPY_*_PASSWORD`
- `WINGPY_*_TOKEN`

See more in the [User Guide](https://wingpy.automation.wingmen.dk/user-guide)

## Usage

Import the class matching the API you want to use. See full list in the [User Guide, API section](https://wingpy.automation.wingmen.dk/api/)

### Connect to an API

Parameters can be specified as environment variables or with static values. It is your responsibility to keep your secrets safe!

```python
from wingpy import CiscoFMC
fmc = CiscoFMC(base_url="https://1.2.3.4", username="admin", password="passw0rd")
```

### Retrieve all items from a paginated API endpoint

Pages are retrieved in parallel for maximum performance.

```python
networks = fmc.get_all("/api/fmc_config/v1/domain/{domainUUID}/object/hosts")
# Domain UUID is automatically substituted.
# Authentication is done automatically when needed.
# Paginated results are automatically fetched and combined.
for network in networks:
    print(network["name"])
```

## Getting help

Check the [FAQ](https://wingpy.automation.wingmen.dk/faq/) or search the [documentation](https://wingpy.automation.wingmen.dk)

To report bugs or request features, please open a GitHub issue.
