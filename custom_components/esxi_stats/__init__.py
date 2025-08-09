"""ESXi Stats Integration."""
import asyncio
import logging
import os
from datetime import datetime, timedelta

from pyVmomi import vim  # pylint: disable=no-name-in-module
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.exceptions import ConfigEntryNotReady
import homeassistant.helpers.config_validation as cv

from homeassistant.const import (
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_VERIFY_SSL,
    __version__ as HAVERSION,
)

from .esxi import (
    esx_connect,
    esx_disconnect,
    check_license,
    get_host_info,
    get_datastore_info,
    get_license_info,
    get_vm_info,
    host_pwr,
    host_pwr_policy,
    vm_pwr,
    vm_snap_take,
    vm_snap_remove,
    list_esxi_hosts,
    list_power_policies,
)

from .const import (
    AVAILABLE_CMND_VM_SNAP,
    AVAILABLE_CMND_VM_POWER,
    AVAILABLE_CMND_HOST_POWER,
    COMMAND,
    DEFAULT_OPTIONS,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    DOMAIN_DATA,
    PLATFORMS,
    REQUIRED_FILES,
    HOST,
    TARGET_HOST,
    VM,
    FORCE,
)

_LOGGER = logging.getLogger(__name__)

HOST_PWR_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
        vol.Optional(TARGET_HOST): cv.string,
        vol.Required(COMMAND): cv.string,
        vol.Required(FORCE): cv.boolean,
    }
)
LIST_HOSTS_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
    }
)
LIST_POWER_POLICIES_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
        vol.Optional(TARGET_HOST): cv.string,
    }
)
HOST_PWR_POLICY_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
        vol.Required(COMMAND): cv.string,
        vol.Optional(TARGET_HOST): cv.string,
    }
)
VM_PWR_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
        vol.Required(VM): cv.string,
        vol.Required(COMMAND): cv.string,
    }
)
SNAP_CREATE_SCHEMA = vol.Schema(
    {vol.Required(HOST): cv.string, vol.Required(VM): cv.string}, extra=vol.ALLOW_EXTRA
)
SNAP_REMOVE_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
        vol.Required(VM): cv.string,
        vol.Required(COMMAND): cv.string,
    }
)
CLEANUP_STALE_SCHEMA = vol.Schema(
    {
        vol.Required(HOST): cv.string,
    }
)
CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.Schema({}, extra=vol.ALLOW_EXTRA)}, extra=vol.ALLOW_EXTRA
)


async def async_setup_entry(hass, config_entry):
    """Set up this integration using UI."""
    conf = hass.data.get(DOMAIN_DATA)
    if config_entry.source == config_entries.SOURCE_IMPORT:
        if conf is None:
            hass.async_create_task(
                hass.config_entries.async_remove(config_entry.entry_id)
            )
        # This is using YAML for configuration
        return False

    # check all required files
    file_check = await hass.async_add_executor_job(check_files, hass)
    if not file_check:
        return False

    config = {DOMAIN: config_entry.data}
    entry = config_entry.entry_id

    # create data dictionary
    if DOMAIN_DATA not in hass.data:
        hass.data[DOMAIN_DATA] = {}
    hass.data[DOMAIN_DATA][entry] = {}
    hass.data[DOMAIN_DATA][entry]["configuration"] = "config_flow"
    hass.data[DOMAIN_DATA][entry]["vmhost"] = {}
    hass.data[DOMAIN_DATA][entry]["datastore"] = {}
    hass.data[DOMAIN_DATA][entry]["license"] = {}
    hass.data[DOMAIN_DATA][entry]["vm"] = {}
    hass.data[DOMAIN_DATA][entry]["monitored_conditions"] = []

    if config_entry.data["vmhost"]:
        hass.data[DOMAIN_DATA][entry]["monitored_conditions"].append("vmhost")
    if config_entry.data["datastore"]:
        hass.data[DOMAIN_DATA][entry]["monitored_conditions"].append("datastore")
    if config_entry.data["license"]:
        hass.data[DOMAIN_DATA][entry]["monitored_conditions"].append("license")

    if config_entry.data["vm"]:
        hass.data[DOMAIN_DATA][entry]["monitored_conditions"].append("vm")

    if not config_entry.options:
        async_update_options(hass, config_entry)

    # get global config
    _LOGGER.debug("Setting up host %s", config[DOMAIN].get(CONF_HOST))
    hass.data[DOMAIN_DATA][entry]["client"] = EsxiStats(hass, config, config_entry)

    lic = await hass.async_add_executor_job(connect, hass, config, entry)

    # load platforms
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    # if lisense allows API write, register services
    if lic:
        async_add_services(hass, config_entry)
    else:
        _LOGGER.info(
            "Service calls are disabled - %s doesn't have a supported license",
            config[DOMAIN]["host"],
        )

    return True


def connect(hass, config, entry):
    """Connect."""
    conn = None
    try:
        conn_details = {
            "host": config[DOMAIN]["host"],
            "user": config[DOMAIN]["username"],
            "pwd": config[DOMAIN]["password"],
            "port": config[DOMAIN]["port"],
            "ssl": config[DOMAIN]["verify_ssl"],
        }

        conn = esx_connect(**conn_details)
        if conn:
            _LOGGER.debug("Product Line: %s", conn.content.about.productLineId)

            # get license type and objects
            lic = check_license(conn.RetrieveContent().licenseManager)
            hass.data[DOMAIN_DATA][entry]["client"].update_data()
        else:
            lic = "n/a"
    except Exception as exception:  # pylint: disable=broad-except
        _LOGGER.error(exception)
        raise ConfigEntryNotReady from exception
    finally:
        if conn:
            esx_disconnect(conn)

    return lic


class EsxiStats:
    """This class handles communication, services, and stores the data."""

    def __init__(self, hass, config, config_entry=None):
        """Initialize the class."""
        self.hass = hass
        self.config = config[DOMAIN]
        self.host = config[DOMAIN].get(CONF_HOST)
        self.user = config[DOMAIN].get(CONF_USERNAME)
        self.passwd = config[DOMAIN].get(CONF_PASSWORD)
        self.port = config[DOMAIN].get(CONF_PORT)
        self.ssl = config[DOMAIN].get(CONF_VERIFY_SSL)

        if config_entry:
            self.entry = config_entry.entry_id
            self._config_entry = config_entry
        else:
            self.entry = None
            self._config_entry = None

        # Get update interval from options, with fallback to default
        update_interval = DEFAULT_UPDATE_INTERVAL
        if config_entry and config_entry.options:
            update_interval = config_entry.options.get("update_interval", DEFAULT_UPDATE_INTERVAL)

        self._update_interval = timedelta(seconds=update_interval)
        self._last_update = None

    def _should_update(self):
        """Check if enough time has passed since last update."""
        if self._last_update is None:
            return True
        time_since_update = datetime.now() - self._last_update
        return time_since_update >= self._update_interval

    def update_data(self):
        """Update data with configurable throttling."""
        # Check if we should update based on our custom interval
        if not self._should_update():
            if self._last_update:
                time_since_update = datetime.now() - self._last_update
                remaining = (self._update_interval - time_since_update).total_seconds()
                _LOGGER.debug("Skipping update - throttled (next update in %.1f seconds)", remaining)
            return

        conn = None
        try:
            # connect and get data from host
            conn = esx_connect(self.host, self.user, self.passwd, self.port, self.ssl)
            content = conn.RetrieveContent()

            # Mark successful update time
            self._last_update = datetime.now()
            _LOGGER.debug("Data updated successfully at %s", self._last_update)

        except Exception as error:  # pylint: disable=broad-except
            _LOGGER.debug("ESXi host is not reachable - skipping update - %s", error)
            # Don't update _last_update on failure so we retry sooner
        else:
            # Track previous entities for cleanup
            previous_entities = {
                'vmhost': set(self.hass.data[DOMAIN_DATA][self.entry]["vmhost"].keys()) if self.config.get("vmhost") is True else set(),
                'vm': set(self.hass.data[DOMAIN_DATA][self.entry]["vm"].keys()) if self.config.get("vm") is True else set(),
                'datastore': set(self.hass.data[DOMAIN_DATA][self.entry]["datastore"].keys()) if self.config.get("datastore") is True else set(),
            }
            # get host stats
            if self.config.get("vmhost") is True:
                # create/destroy view objects
                host_objview = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.HostSystem], True
                )
                esxi_hosts = host_objview.view
                host_objview.Destroy()

                # Look through object list and get data
                _LOGGER.debug("Found %s host(s)", len(esxi_hosts))
                for esxi_host in esxi_hosts:
                    host_name = esxi_host.summary.config.name.replace(" ", "_").lower()

                    _LOGGER.debug("Getting stats for vmhost: %s", host_name)
                    self.hass.data[DOMAIN_DATA][self.entry]["vmhost"][
                        host_name
                    ] = get_host_info(esxi_host)

            # get datastore stats
            if self.config.get("datastore") is True:
                # create/destroy view objects
                ds_objview = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.Datastore], True
                )
                ds_list = ds_objview.view
                ds_objview.Destroy()

                # Look through object list and get data
                _LOGGER.debug("Found %s datastore(s)", len(ds_list))
                for datastore in ds_list:
                    ds_name = datastore.summary.name.replace(" ", "_").lower()

                    _LOGGER.debug("Getting stats for datastore: %s", ds_name)
                    self.hass.data[DOMAIN_DATA][self.entry]["datastore"][
                        ds_name
                    ] = get_datastore_info(datastore)

            # get license stats
            if self.config.get("license") is True:
                lic_list = content.licenseManager

                # Get all hosts for better context
                host_objview = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.HostSystem], True
                )
                esxi_hosts = host_objview.view
                host_objview.Destroy()

                _LOGGER.debug("Found %s license(s) and %s host(s)", len(lic_list.licenses), len(esxi_hosts))

                # Collect host names for reference
                host_names = []
                for esxi_host in esxi_hosts:
                    host_names.append({
                        'name': esxi_host.summary.config.name.replace(" ", "_").lower(),
                        'original_name': esxi_host.summary.config.name
                    })

                # Process each license and assign meaningful names
                vcenter_license_count = 0
                esxi_license_count = 0
                other_license_count = 0
                processed_license_keys = set()  # Track processed license keys to avoid duplicates
                valid_licenses = []  # Collect valid licenses first (skip only clearly invalid products)

                # First pass: collect all valid licenses (skip only clearly invalid ones)
                for lic in lic_list.licenses:
                    product_name = None  # Start with None to detect missing ProductName
                    license_key = getattr(lic, 'licenseKey', None) or getattr(lic, 'name', None)
                    license_name = getattr(lic, 'name', '')

                    for key in lic.properties:
                        if key.key == "ProductName":
                            product_name = key.value
                            break

                    _LOGGER.debug("Checking license: name='%s', product='%s'", license_name, product_name)

                    # Skip licenses without a valid ProductName (will result in product='n/a' in entity)
                    if product_name is None or product_name == "n/a":
                        _LOGGER.warning("Filtering out invalid license: name='%s', product='%s'", license_name, product_name)
                        continue

                    valid_licenses.append(lic)

                # Second pass: process valid licenses
                for lic in valid_licenses:
                    # Determine product type for better naming
                    product_name = "unknown"
                    license_key = getattr(lic, 'licenseKey', None) or getattr(lic, 'name', None)
                    license_name = getattr(lic, 'name', '')

                    for key in lic.properties:
                        if key.key == "ProductName":
                            product_name = key.value
                            break

                    product_name_lower = product_name.lower()

                    # Skip if we've already processed this license key (same license used by multiple hosts)
                    if license_key and license_key in processed_license_keys:
                        continue

                    # Determine entity name based on product and environment
                    if "vcenter" in product_name_lower or "vpx" in product_name_lower or "virtualcenter" in product_name_lower:
                        # vCenter Server license - create one entity
                        entity_name = "vcenter_license"
                        associated_host = self.host  # vCenter server itself

                        # Mark this license key as processed
                        if license_key:
                            processed_license_keys.add(license_key)

                        _LOGGER.debug("Created vCenter license entity")
                        self.hass.data[DOMAIN_DATA][self.entry]["license"][
                            entity_name
                        ] = get_license_info(lic, associated_host)

                    elif ("esx" in product_name_lower or
                          "vmware_esx" in product_name_lower or
                          product_name_lower.startswith("vmware esx") or
                          "esxi" in product_name_lower):
                        # ESXi host license - create separate entities for each host, even with shared licenses
                        for host_info in host_names:
                            entity_name = f"{host_info['name']}_license"
                            associated_host = host_info['original_name']

                            self.hass.data[DOMAIN_DATA][self.entry]["license"][
                                entity_name
                            ] = get_license_info(lic, associated_host)

                        # Mark this license key as processed
                        if license_key:
                            processed_license_keys.add(license_key)
                        esxi_license_count += 1
                    else:
                        # Other/unknown license types
                        _LOGGER.warning("Unknown license product type: '%s' - please report this for better detection", product_name)
                        other_license_count += 1

                        # For unknown licenses, create entities for each host if we have hosts
                        if len(esxi_hosts) > 0:
                            _LOGGER.info("Treating unknown license as ESXi license for hosts: %s", ", ".join([host['original_name'] for host in host_names]))
                            for host_info in host_names:
                                entity_name = f"{host_info['name']}_unknown_license_{other_license_count}"
                                associated_host = host_info['original_name']

                                self.hass.data[DOMAIN_DATA][self.entry]["license"][
                                    entity_name
                                ] = get_license_info(lic, associated_host)
                        else:
                            # No hosts - create generic entity
                            clean_product = product_name_lower.replace(" ", "_").replace("-", "_")
                            if clean_product == "unknown":
                                entity_name = f"unknown_license_{other_license_count}"
                            else:
                                entity_name = f"{clean_product}_license"
                            associated_host = self.host

                            self.hass.data[DOMAIN_DATA][self.entry]["license"][
                                entity_name
                            ] = get_license_info(lic, associated_host)

                        # Mark this license key as processed
                        if license_key:
                            processed_license_keys.add(license_key)            # get vm stats
            if self.config.get("vm") is True:
                # create/destroy view objects
                vm_objview = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.VirtualMachine], True
                )
                vm_list = vm_objview.view
                vm_objview.Destroy()

                # Look through object list and get data
                _LOGGER.debug("Found %s VM(s)", len(vm_list))
                for virtual_machine in vm_list:
                    vm_name = virtual_machine.summary.config.name.replace(
                        " ", "_"
                    ).lower()

                    _LOGGER.debug("Getting stats for vm: %s", vm_name)
                    self.hass.data[DOMAIN_DATA][self.entry]["vm"][
                        vm_name
                    ] = get_vm_info(virtual_machine)

            # Clean up stale entities after all data has been collected
            # Check if auto-cleanup is enabled
            if self._config_entry and self._config_entry.options.get("auto_cleanup_stale_entities", False):
                self._cleanup_stale_entities(previous_entities)
        finally:
            if conn is not None:
                esx_disconnect(conn)

    def _cleanup_stale_entities(self, previous_entities):
        """Clean up entities that no longer exist on ESXi."""
        current_entities = {
            'vmhost': set(self.hass.data[DOMAIN_DATA][self.entry]["vmhost"].keys()) if self.config.get("vmhost") is True else set(),
            'vm': set(self.hass.data[DOMAIN_DATA][self.entry]["vm"].keys()) if self.config.get("vm") is True else set(),
            'datastore': set(self.hass.data[DOMAIN_DATA][self.entry]["datastore"].keys()) if self.config.get("datastore") is True else set(),
        }

        for entity_type in ['vmhost', 'vm', 'datastore']:
            stale_entities = previous_entities[entity_type] - current_entities[entity_type]

            if stale_entities:
                _LOGGER.info("Found %d stale %s entities: %s", len(stale_entities), entity_type, list(stale_entities))

                for stale_entity in stale_entities:
                    # Remove from our data store
                    if stale_entity in self.hass.data[DOMAIN_DATA][self.entry][entity_type]:
                        _LOGGER.info("Removing stale %s entity: %s", entity_type, stale_entity)
                        del self.hass.data[DOMAIN_DATA][self.entry][entity_type][stale_entity]

                        # Schedule entity registry cleanup
                        self.hass.async_create_task(
                            self._remove_stale_entity_from_registry(entity_type, stale_entity)
                        )

    async def _remove_stale_entity_from_registry(self, entity_type, entity_name):
        """Remove stale entities from the entity registry."""
        try:
            from homeassistant.helpers import entity_registry as er
            from homeassistant.helpers import device_registry as dr

            entity_registry = er.async_get(self.hass)
            device_registry = dr.async_get(self.hass)

            # Find and remove all related entities for this object
            entities_to_remove = []
            device_ids_to_check = set()

            # Generate possible unique IDs for this entity
            host_part = self.host.replace(".", "_")
            base_unique_id = f"{host_part}_{self.entry}_{entity_type}_{entity_name}"

            # Find entities that match our naming patterns
            for entity_id, entry in entity_registry.entities.items():
                if entry.unique_id and entry.unique_id.startswith(base_unique_id):
                    entities_to_remove.append(entity_id)
                    # Track device IDs for potential cleanup
                    if entry.device_id:
                        device_ids_to_check.add(entry.device_id)

            # Remove the entities
            for entity_id in entities_to_remove:
                _LOGGER.info("Removing stale entity from registry: %s", entity_id)
                entity_registry.async_remove(entity_id)

            # Check if devices should be removed (when all entities for a device are gone)
            for device_id in device_ids_to_check:
                # Count remaining entities for this device
                remaining_entities = [
                    entity_id for entity_id, entry in entity_registry.entities.items()
                    if entry.device_id == device_id
                ]

                # If no entities remain for this device, remove the device
                if not remaining_entities:
                    device_entry = device_registry.async_get(device_id)
                    if device_entry and device_entry.identifiers:
                        # Only remove devices that belong to our integration
                        for identifier_tuple in device_entry.identifiers:
                            if identifier_tuple[0] == DOMAIN:
                                _LOGGER.info("Removing stale device from registry: %s", device_entry.name)
                                device_registry.async_remove_device(device_id)
                                break

            if entities_to_remove:
                _LOGGER.info("Successfully removed %d stale entities for %s '%s'",
                           len(entities_to_remove), entity_type, entity_name)
            else:
                _LOGGER.debug("No registry entries found for stale %s '%s'", entity_type, entity_name)

        except Exception as e:
            _LOGGER.error("Failed to remove stale entity %s '%s' from registry: %s",
                         entity_type, entity_name, str(e))


def check_files(hass):
    """Return bool that indicates if all files are present."""
    base = f"{hass.config.path()}/custom_components/{DOMAIN}/"
    missing = []
    for file in REQUIRED_FILES:
        fullpath = f"{base}{file}"
        if not os.path.exists(fullpath):
            missing.append(file)

    if missing:
        _LOGGER.critical("The following files are missing: %s", str(missing))
        returnvalue = False
    else:
        returnvalue = True

    return returnvalue


@callback
def async_add_services(hass, config_entry):
    """Add ESXi Stats services."""

    # Set notify here - but there has to be a better way
    if (
        "notify" in config_entry.options.keys()
        and config_entry.options["notify"] is not None  # noqa: W503
    ):
        notify = config_entry.options["notify"]
    else:
        notify = True
        _LOGGER.debug("Notify key is missing. Setting notification to true")

    # Check that a host exists in HomeAssistant and get its credentials
    @callback
    def async_get_conn_details(host):
        for _entry in hass.config_entries.async_entries(DOMAIN):
            if host == _entry.data.get("host"):
                return {
                    "host": _entry.data.get("host"),
                    "user": _entry.data.get("username"),
                    "pwd": _entry.data.get("password"),
                    "port": _entry.data.get("port"),
                    "ssl": _entry.data.get("verify_ssl"),
                }

        raise ValueError("Host is not configured in HomeAssistant")

    # Host shutdown service
    async def host_power(call):
        host = call.data["host"]
        target_host = call.data.get("target_host")  # Optional for vCenter multi-host
        cmnd = call.data["command"]
        forc = call.data["force"]

        if cmnd in AVAILABLE_CMND_HOST_POWER:
            try:
                conn_details = async_get_conn_details(host)
                await hass.async_add_executor_job(
                    host_pwr, hass, target_host, cmnd, conn_details, forc, notify
                )
            except Exception as error:  # pylint: disable=broad-except
                _LOGGER.error(str(error))
        else:
            _LOGGER.error("host_power: '%s' is not a supported command", cmnd)

    # List hosts service (useful for vCenter environments)
    async def list_hosts(call):
        host = call.data["host"]

        try:
            conn_details = async_get_conn_details(host)
            await hass.async_add_executor_job(
                list_esxi_hosts, hass, conn_details
            )
        except Exception as error:  # pylint: disable=broad-except
            _LOGGER.error(str(error))

    async def list_power_policies(call):
        host = call.data["host"]
        target_host = call.data.get("target_host")

        try:
            conn_details = async_get_conn_details(host)
            await hass.async_add_executor_job(
                list_power_policies, hass, target_host, conn_details
            )
        except Exception as error:  # pylint: disable=broad-except
            _LOGGER.error(str(error))

    @callback
    def async_get_vm_details(vm_name):
        for _entry in hass.data[DOMAIN_DATA]:
            if vm_name in hass.data[DOMAIN_DATA][_entry]["vm"]:
                return hass.data[DOMAIN_DATA][_entry]["vm"][vm_name]["uuid"]

        raise ValueError("VM UUID not found")

    # Host Power Policy service
    async def host_power_policy(call):
        host = call.data["host"]
        cmnd = call.data["command"]
        target_host = call.data.get("target_host")

        try:
            conn_details = async_get_conn_details(host)
            await hass.async_add_executor_job(host_pwr_policy, target_host, cmnd, conn_details)
        except Exception as error:  # pylint: disable=broad-except
            _LOGGER.error(str(error))

    # VM power service
    async def vm_power(call):
        host = call.data["host"]
        vm_name = call.data["vm"]
        vm_uuid = async_get_vm_details(vm_name)
        cmnd = call.data["command"]

        if cmnd in AVAILABLE_CMND_VM_POWER:
            try:
                conn_details = async_get_conn_details(host)
                await hass.async_add_executor_job(
                    vm_pwr, hass, host, vm_name, vm_uuid, cmnd, conn_details, notify
                )
            except Exception as error:  # pylint: disable=broad-except
                _LOGGER.error(str(error))
        else:
            _LOGGER.error("vm_power: '%s' is not a supported command", cmnd)

    # Snapshot create service
    async def snap_create(call):
        host = call.data["host"]
        vm_name = call.data["vm"]
        vm_uuid = async_get_vm_details(vm_name)
        memory = False
        quiesce = False
        now = datetime.now()
        name = f"snapshot_{now.strftime('%Y%m%d_%H%M%S')}"  # Default name
        desc = "Taken from HASS (" + HAVERSION + ") on " + now.strftime("%x %X")

        if "name" in call.data:
            name = call.data["name"]
        if "description" in call.data:
            desc = call.data["description"]
        if "memory" in call.data:
            memory = call.data["memory"]
        if "quiesce" in call.data:
            quiesce = call.data["quiesce"]

        try:
            conn_details = async_get_conn_details(host)
            hass.async_add_executor_job(
                vm_snap_take,
                hass,
                host,
                vm_name,
                vm_uuid,
                name,
                desc,
                memory,
                quiesce,
                conn_details,
                notify,
            )
        except Exception as error:  # pylint: disable=broad-except
            _LOGGER.error(str(error))

    # Snapshot remove service
    async def snap_remove(call):
        host = call.data["host"]
        vm_name = call.data["vm"]
        vm_uuid = async_get_vm_details(vm_name)
        cmnd = call.data["command"]

        if cmnd in AVAILABLE_CMND_VM_SNAP:
            try:
                conn_details = async_get_conn_details(host)
                hass.async_add_executor_job(
                    vm_snap_remove,
                    hass,
                    host,
                    vm_name,
                    vm_uuid,
                    cmnd,
                    conn_details,
                    notify,
                )
            except Exception as error:  # pylint: disable=broad-except
                _LOGGER.error(str(error))
        else:
            _LOGGER.error("snap_remove: '%s' is not a supported command", cmnd)

    # Cleanup stale entities service
    async def cleanup_stale_entities(call):
        host = call.data["host"]

        try:
            # Find the config entry for this host
            config_entry = None
            for _entry in hass.config_entries.async_entries(DOMAIN):
                if host == _entry.data.get("host"):
                    config_entry = _entry
                    break

            if not config_entry:
                _LOGGER.error("Host '%s' is not configured in HomeAssistant", host)
                return

            # Get the client and force an update to get current ESXi state
            client = hass.data[DOMAIN_DATA][config_entry.entry_id]["client"]

            # Store previous entities before update
            previous_entities = {
                'vmhost': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["vmhost"].keys()) if client.config.get("vmhost") is True else set(),
                'vm': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["vm"].keys()) if client.config.get("vm") is True else set(),
                'datastore': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["datastore"].keys()) if client.config.get("datastore") is True else set(),
            }

            # Force data update to get current state from ESXi
            client._last_update = None  # Reset to force update
            client.update_data()

            # Get current entities after update
            current_entities = {
                'vmhost': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["vmhost"].keys()) if client.config.get("vmhost") is True else set(),
                'vm': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["vm"].keys()) if client.config.get("vm") is True else set(),
                'datastore': set(hass.data[DOMAIN_DATA][config_entry.entry_id]["datastore"].keys()) if client.config.get("datastore") is True else set(),
            }

            # Find and clean up stale entities
            stale_count = 0
            for entity_type in ['vmhost', 'vm', 'datastore']:
                stale_entities = previous_entities[entity_type] - current_entities[entity_type]
                stale_count += len(stale_entities)

                if stale_entities:
                    _LOGGER.info("Manual cleanup: Found %d stale %s entities: %s",
                               len(stale_entities), entity_type, list(stale_entities))

                    for stale_entity in stale_entities:
                        await client._remove_stale_entity_from_registry(entity_type, stale_entity)

            # Create notification with results
            from homeassistant.components import persistent_notification
            if stale_count > 0:
                message = f"Cleanup completed: Removed {stale_count} stale entities from {host}"
                _LOGGER.info(message)
            else:
                message = f"Cleanup completed: No stale entities found on {host}"
                _LOGGER.info(message)

            persistent_notification.create(hass, message, "ESXi Stats Cleanup")

        except Exception as error:  # pylint: disable=broad-except
            error_msg = f"Failed to cleanup stale entities for {host}: {str(error)}"
            _LOGGER.error(error_msg)
            from homeassistant.components import persistent_notification
            persistent_notification.create(hass, error_msg, "ESXi Stats Cleanup Error")

    hass.services.async_register(DOMAIN, "vm_power", vm_power, schema=VM_PWR_SCHEMA)
    hass.services.async_register(
        DOMAIN, "host_power", host_power, schema=HOST_PWR_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, "list_hosts", list_hosts, schema=LIST_HOSTS_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, "list_power_policies", list_power_policies, schema=LIST_POWER_POLICIES_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, "create_snapshot", snap_create, schema=SNAP_CREATE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, "remove_snapshot", snap_remove, schema=SNAP_REMOVE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN,
        "host_power_policy",
        host_power_policy,
        schema=HOST_PWR_POLICY_SCHEMA,
    )
    hass.services.async_register(
        DOMAIN, "cleanup_stale_entities", cleanup_stale_entities, schema=CLEANUP_STALE_SCHEMA
    )


async def async_unload_entry(hass, config_entry):
    """Handle removal of an entry."""
    if hass.data.get(DOMAIN_DATA, {}).get("configuration") == "yaml":
        hass.async_create_task(
            hass.config_entries.flow.async_init(
                DOMAIN, context={"source": config_entries.SOURCE_IMPORT}, data={}
            )
        )
    else:
        await asyncio.gather(
            *[
                hass.config_entries.async_forward_entry_unload(config_entry, platform)
                for platform in PLATFORMS
            ]
        )
        _LOGGER.info("Successfully removed the ESXi Stats integration")

    return True


@callback
def async_update_options(hass, config_entry):
    """Update config entry options"""
    hass.config_entries.async_update_entry(config_entry, options=DEFAULT_OPTIONS)
