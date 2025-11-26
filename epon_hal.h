#ifndef _EPON_HAL_H_
#define _EPON_HAL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief EPON HAL API version
 * 
 * Version format: Major.Minor.Patch
 * - Major version changes: Incompatible API/ABI changes
 * - Minor version changes: Backwards-compatible additions
 * - Patch version changes: Backwards-compatible bug fixes
 * 
 * Applications should check version compatibility at runtime using epon_hal_get_version()
 */
#define EPON_HAL_VERSION_MAJOR 1
#define EPON_HAL_VERSION_MINOR 0
#define EPON_HAL_VERSION_PATCH 0
#define EPON_HAL_MAKE_VERSION(major, minor, patch) ((major << 24) | (minor << 16) | (patch))
#define EPON_HAL_API_VERSION EPON_HAL_MAKE_VERSION(EPON_HAL_VERSION_MAJOR, EPON_HAL_VERSION_MINOR, EPON_HAL_VERSION_PATCH)

/**
 * @brief Buffer length constants
 */
#define EPON_HAL_MAC_ADDR_LEN 6              /**< MAC address length in bytes */
#define EPON_HAL_VENDOR_OUI_LEN 3            /**< Vendor OUI length in bytes */
#define EPON_HAL_MANUFACTURER_LEN 32         /**< Manufacturer name buffer length */
#define EPON_HAL_MODEL_NUMBER_LEN 16         /**< Model number buffer length */
#define EPON_HAL_HW_VERSION_LEN 16           /**< Hardware version buffer length */
#define EPON_HAL_SW_VERSION_LEN 16           /**< Software version buffer length */
#define EPON_HAL_SERIAL_NUMBER_LEN 32        /**< Serial number buffer length */
#define EPON_HAL_MODE_LEN 16                 /**< Operational mode buffer length */
#define EPON_HAL_MAX_INTERFACES 16           /**< Maximum number of interfaces */
#define EPON_HAL_INTERFACE_NAME_LEN 32       /**< Interface name buffer length */

/**
 * @defgroup HAL_LOGGER Generic HAL Logging APIs
 * @brief Generic logging macros for HAL modules - implementer defines the backend
 * @{
 */

/**
 * @brief Generic HAL log levels
 */
typedef enum {
    HAL_LOG_LEVEL_FATAL = 0,    /**< Fatal errors - critical failures */
    HAL_LOG_LEVEL_ERROR,        /**< Error conditions */
    HAL_LOG_LEVEL_WARN,         /**< Warning conditions */
    HAL_LOG_LEVEL_NOTICE,       /**< Normal but significant conditions */
    HAL_LOG_LEVEL_INFO,         /**< Informational messages */
    HAL_LOG_LEVEL_DEBUG,        /**< Debug-level messages */
    HAL_LOG_LEVEL_TRACE         /**< Trace-level detailed messages */
} hal_log_level_t;

/**
 * @brief Generic HAL logging macro
 * 
 * HAL implementer uses this macro to log messages at any level. The actual logging
 * backend can be customized by defining HAL_LOG_FUNCTION before including this header.
 *
 * @param level Log level (hal_log_level_t enum value)
 * @param format printf-style format string
 * @param ... Variable arguments matching the format string
 *
 * Example usage:
 * @code
 * HAL_LOG(HAL_LOG_LEVEL_ERROR, "Failed to initialize: %s", error_msg);
 * HAL_LOG(HAL_LOG_LEVEL_INFO, "Device registered successfully");
 * HAL_LOG(HAL_LOG_LEVEL_DEBUG, "Counter value: %d", counter);
 * @endcode
 */
#define HAL_LOG(level, format, ...)   HAL_LOG_FUNCTION(level, __FUNCTION__, __LINE__, format, ##__VA_ARGS__)

/**
 * @brief Logging backend function - can be customized by defining HAL_LOG_FUNCTION
 * 
 * By default, logging is disabled (no-op). To enable logging, define HAL_LOG_FUNCTION
 * before including this header to redirect to your preferred logging backend.
 * 
 * Example for RDK Logger:
 * @code
 * #define HAL_LOG_FUNCTION(level, func, line, format, ...) \
 *     RDK_LOG(rdk_log_map[level], "LOG.RDK.HAL", "[%s:%d] " format, func, line, ##__VA_ARGS__)
 * @endcode
 * 
 * Example for printf:
 * @code
 * #define HAL_LOG_FUNCTION(level, func, line, format, ...) \
 *     printf("[HAL][%s:%d] " format "\n", func, line, ##__VA_ARGS__)
 * @endcode
 * 
 * Example for syslog:
 * @code
 * #define HAL_LOG_FUNCTION(level, func, line, format, ...) \
 *     syslog(syslog_map[level], "[%s:%d] " format, func, line, ##__VA_ARGS__)
 * @endcode
 */
#ifndef HAL_LOG_FUNCTION
#define HAL_LOG_FUNCTION(level, func, line, format, ...) /* Logging disabled by default */
#endif

/** @} */ /* End of HAL_LOGGER group */

/**
 * @brief EPON HAL return values
 */
typedef enum {
    EPON_HAL_SUCCESS = 0,                   /**< Operation completed successfully. */
    EPON_HAL_ERROR_INVALID_PARAM = -1,      /**< Invalid parameter provided. */
    EPON_HAL_ERROR_NOT_INITIALIZED = -2,    /**< HAL not initialized. */
    EPON_HAL_ERROR_HW_FAILURE = -3,         /**< Hardware operation failed. */
    EPON_HAL_ERROR_NOT_SUPPORTED = -4,      /**< Operation not supported. */
    EPON_HAL_ERROR_TIMEOUT = -5,            /**< Operation timeout. */
    EPON_HAL_ERROR_MEMORY = -6,             /**< Memory allocation failed. */
    EPON_HAL_ERROR_RESOURCE = -7,           /**< Resource unavailable. */
    EPON_HAL_ERROR_CALLBACK_REG = -8,       /**< Callback registration failed. */
    EPON_HAL_ERROR_CONFIG = -9,             /**< Configuration error. */
    EPON_HAL_ERROR = -10                    /**< General error. */
} epon_hal_return_t;

typedef enum {
    EPON_ONU_STATUS_LOS =0 ,                    /**< PHY down: Physical layer is down or not detected. No signal  */
    EPON_ONU_STATUS_LINK_DOWN,                  /**< Link down: link lost. */ 
    EPON_ONU_STATUS_DOWNSTREAM_SIGNAL_DETECTED, /**< Downstream signal detected (power present, ONU not yet registered). */
    EPON_ONU_STATUS_FAULT,                      /**< Fault state: Only downstream power detected (possible wrong OLT). */
    EPON_ONU_STATUS_MPCP_DISCOVERY_TIMEOUT,     /**< MPCP discovery timeout: No GATE message received during discovery. */
    EPON_ONU_STATUS_MPCP_REGISTER_TIMEOUT,      /**< MPCP registration timeout: REGISTER_REQ sent but no REGISTER/GATE received. */
    EPON_ONU_STATUS_MPCP_REGISTER_ACK_TIMEOUT,  /**< MPCP registration ACK timeout: REGISTER_ACK sent but no acknowledgment. */
    EPON_ONU_STATUS_MPCP_REGISTERED,            /**< MPCP registration completed. */
    EPON_ONU_STATUS_OAM_REGISTERED,             /**< OAM registration completed. */
    EPON_ONU_STATUS_DEREGISTRATION,             /**< ONU deregistered from OLT. */
    EPON_ONU_STATUS_LINK_UP,                    /**< Link up: ONU registered and interface (veip0) is up. */
} epon_onu_status_t;

typedef enum {
    
    EPON_HAL_ALARM_LOS = 0,                 /**< Loss of signal detected. */
    EPON_HAL_ALARM_LOFI,                    /**< Loss of frame/lock. */
    EPON_HAL_ALARM_DYING_GASP,              /**< Imminent power loss detected. */
    EPON_HAL_ALARM_CRITICAL_EVENT,          /**< Critical event occurred. */
    EPON_HAL_ALARM_LINK_FAULT,              /**< Link fault detected. */
    EPON_HAL_ALARM_ERROR_SYMBOL_PERIOD,     /**< Errored symbol period threshold exceeded. */
    EPON_HAL_ALARM_ERROR_FRAME,             /**< Errored frame threshold exceeded. */
    EPON_HAL_ALARM_ERROR_FRAME_PERIOD,      /**< Errored frame period threshold exceeded. */
    EPON_HAL_ALARM_ERROR_FRAME_SECONDS,     /**< Errored frame seconds threshold exceeded. */
    EPON_HAL_ALARM_OAM_SESSION_LOST,        /**< OAM session lost. */
    EPON_HAL_ALARM_POWER_LOW,               /**< Optical power below threshold. */
    EPON_HAL_ALARM_POWER_HIGH,              /**< Optical power above threshold. */
    EPON_HAL_ALARM_EQUIPMENT_FAILURE,       /**< Equipment or hardware failure. */
    EPON_HAL_ALARM_TEMPERATURE,             /**< Temperature threshold exceeded. */
    EPON_HAL_ALARM_VENDOR_SPECIFIC,         /**< Vendor-specific OAM alarm. */
    EPON_HAL_ALARM_FEC_THRESHOLD,           /**< FEC uncorrectable errors threshold exceeded. */
    EPON_HAL_ALARM_LASER_BIAS_CURRENT,      /**< Laser bias current out of range. */
    EPON_HAL_ALARM_SUPPLY_VOLTAGE,          /**< Supply voltage out of range. */
    EPON_HAL_ALARM_TX_FAULT,                /**< Transmitter fault detected. */
    EPON_HAL_ALARM_RX_FAULT,                /**< Receiver fault detected. */
    EPON_HAL_ALARM_MAX                      /**< Maximum alarm value (not an actual alarm). */
} epon_hal_alarm_t;

/**
 * @brief OAM message types for logging (IEEE 802.3ah)
 * Bitmask values to enable/disable logging of specific OAM message types.
 */
typedef enum {
    EPON_OAM_INFO           = (1 << 0),  /**< OAM Information PDU (0x00). */
    EPON_OAM_EVENT          = (1 << 1),  /**< OAM Event Notification (0x01). */
    EPON_OAM_VAR_REQUEST    = (1 << 2),  /**< OAM Variable Request (0x02). */
    EPON_OAM_VAR_RESPONSE   = (1 << 3),  /**< OAM Variable Response (0x03). */
    EPON_OAM_LOOPBACK       = (1 << 4),  /**< OAM Loopback Control (0x04). */
    EPON_OAM_ORG_SPECIFIC   = (1 << 5),  /**< OAM Organization Specific (0xFE). */
    EPON_OAM_MPCP_REGISTER  = (1 << 6),  /**< MPCP REGISTER message. */
    EPON_OAM_MPCP_GATE      = (1 << 7),  /**< MPCP GATE message. */
    EPON_OAM_MPCP_REPORT    = (1 << 8),  /**< MPCP REPORT message. */
    EPON_OAM_MPCP_REGISTER_ACK = (1 << 9), /**< MPCP REGISTER_ACK message. */
    EPON_OAM_ALL            = 0xFFFFFFFF /**< Enable logging for all OAM messages. */
} epon_oam_log_type_t;

/**
 * @brief EPON link statistics (TR-181: Device.Optical.Interface.{i}.Stats)
 * 
 * @note Caller MUST set struct_size to sizeof(epon_hal_link_stats_t) before calling any API.
 */
typedef struct {
    uint32_t struct_size;            /**< Size of this structure - MUST be set by caller to sizeof(epon_hal_link_stats_t) */
    uint64_t packets_sent;           /**< Total packets transmitted (TR-181: PacketsSent). */
    uint64_t packets_received;       /**< Total packets received (TR-181: PacketsReceived). */
    uint64_t bytes_sent;             /**< Total bytes transmitted (TR-181: BytesSent). */
    uint64_t bytes_received;         /**< Total bytes received (TR-181: BytesReceived). */
    uint64_t errors_sent;            /**< Errors on transmission (TR-181: ErrorsSent). */
    uint64_t errors_received;        /**< Errors on reception (TR-181: ErrorsReceived). */
    uint64_t discard_packets_sent;   /**< Packets discarded prior to transmission (TR-181: DiscardPacketsSent). */
    uint64_t discard_packets_received; /**< Packets discarded on reception (TR-181: DiscardPacketsReceived). */
    uint32_t max_bit_rate;           /**< Maximum bit rate in Mbps (TR-181: MaxBitRate). */
    uint64_t fec_corrected;          /**< Number of FEC corrected codewords (EPON extension). */
    uint64_t fec_uncorrectable;      /**< Number of uncorrectable codewords (EPON extension). */
    uint64_t broadcast_packets_sent; /**< Broadcast packets transmitted (EPON extension). */
    uint64_t broadcast_packets_received; /**< Broadcast packets received (EPON extension). */
    uint64_t multicast_packets_sent; /**< Multicast packets transmitted (EPON extension). */
    uint64_t multicast_packets_received; /**< Multicast packets received (EPON extension). */
    uint64_t ranging_resyncs;        /**< Number of ranging resynchronisations (EPON extension). */ 
    uint64_t mac_resets;             /**< Number of MAC resets (EPON extension). */
} epon_hal_link_stats_t;

/**
 * @brief Transceiver (optical) statistics (TR-181: Device.Optical.Interface.{i})
 * 
 * @note Caller MUST set struct_size to sizeof(epon_hal_transceiver_stats_t) before calling any API.
 */
typedef struct {
    uint32_t struct_size;            /**< Size of this structure - MUST be set by caller to sizeof(epon_hal_transceiver_stats_t) */
    float transmit_optical_level;    /**< Transmit optical power in dBm (TR-181: TransmitOpticalLevel). */
    float optical_signal_level;      /**< Receive optical power in dBm (TR-181: OpticalSignalLevel). */
    float lower_optical_threshold;   /**< Lower receive optical power threshold in dBm (TR-181: LowerOpticalThreshold). */
    float upper_optical_threshold;   /**< Upper receive optical power threshold in dBm (TR-181: UpperOpticalThreshold). */
    float lower_transmit_power_threshold; /**< Lower transmit optical power threshold in dBm (TR-181: LowerTransmitPowerThreshold). */
    float upper_transmit_power_threshold; /**< Upper transmit optical power threshold in dBm (TR-181: UpperTransmitPowerThreshold). */
    float bias_current_ma;           /**< Laser bias current in mA (vendor extension). */
    float temperature_c;             /**< Module temperature in Celsius (vendor extension). */
    float supply_voltage_v;          /**< Supply voltage in volts (vendor extension). */
} epon_hal_transceiver_stats_t;


typedef enum {
    EPON_LLID_MODE_UNICAST = 0, /**< Unicast mode (P2P emulation) Used for unicast communication between OLT and specific ONU */
    EPON_LLID_MODE_BROADCAST = 1 /**< Broadcast/Multicast mode (Shared emulation) Used for broadcast messages to all ONUs or multicast groups */
} epon_llid_mode_t;

typedef enum {
    EPON_LLID_STATE_UNREGISTERED = 0,   /**< LLID not assigned, ONU not registered */
    EPON_LLID_STATE_REGISTERING = 1,    /**< LLID assignment in progress */
    EPON_LLID_STATE_REGISTERED = 2,     /**< LLID assigned, ONU registered */
    EPON_LLID_STATE_DEREGISTERING = 3,  /**< LLID being released, deregistration in progress */
    EPON_LLID_STATE_FAILED = 4          /**< Registration failed or link failure */
} epon_llid_state_t;

typedef enum {
    EPON_LLID_FORWARDING_DISABLED = 0,  /**< LLID forwarding disabled, traffic blocked */
    EPON_LLID_FORWARDING_ENABLED = 1,   /**< LLID forwarding enabled, traffic allowed */
    EPON_LLID_FORWARDING_LEARNING = 2   /**< LLID in learning state, limited forwarding */
} epon_llid_forwarding_state_t;

/**
 * @brief LLID information structure
 * 
 * @note This structure is allocated and filled by HAL implementation.
 */
typedef struct {
    uint16_t llid_value;                           /**< Logical Link Identifier value. */
    epon_llid_mode_t mode;
    epon_llid_state_t state;
    epon_llid_forwarding_state_t forwarding_state; /**< Current forwarding state of the LLID. */
    uint8_t local_mac_address[EPON_HAL_MAC_ADDR_LEN]; /**< Local MAC address associated with this LLID. */
    uint8_t dscp_marking;                          /**< DSCP value to mark on egress traffic (0-63). */
} epon_llid_info_t;

typedef struct {
    uint32_t max_llid_count;        /**< Maximum number of LLIDs supported. */
    uint32_t llid_count;            /**< Total number of LLIDs currently configured/active */
    epon_llid_info_t *llid_list;    /**< Pointer to array of LLID information structures. */
} epon_llid_list_t;



typedef struct {
    uint32_t struct_size;                                 /**< Size of this structure - MUST be set by caller to sizeof(epon_onu_manufacturer_info_t) */
    char manufacturer[EPON_HAL_MANUFACTURER_LEN];         /**< Manufacturer name (TR-181: Device.DeviceInfo.Manufacturer). */
    char model_number[EPON_HAL_MODEL_NUMBER_LEN];         /**< Model number (TR-181: Device.DeviceInfo.ModelNumber). */
    char hardware_version[EPON_HAL_HW_VERSION_LEN];     /**< Hardware version (TR-181: Device.DeviceInfo.HardwareVersion). */
    char software_version[EPON_HAL_SW_VERSION_LEN];     /**< Software/firmware version (TR-181: Device.DeviceInfo.SoftwareVersion). */
    char serial_number[EPON_HAL_SERIAL_NUMBER_LEN];        /**< Device serial number (TR-181: Device.DeviceInfo.SerialNumber). */
    uint8_t vendor_oui[EPON_HAL_VENDOR_OUI_LEN];         /**< Vendor OUI (Organizationally Unique Identifier). */
} epon_onu_manufacturer_info_t;


typedef enum {
    EPON_ENCRYPTION_MODE_DISABLED = 0,      /**< Encryption disabled, no data encryption. */
    EPON_ENCRYPTION_MODE_AES_128 = 1,       /**< AES-128 encryption mode as per IEEE 802.3ah. */
    EPON_ENCRYPTION_MODE_TRIPLE_CHURNING = 2, /**< Triple churning encryption mode. */
    EPON_ENCRYPTION_MODE_AES_256 = 3,       /**< AES-256 encryption mode (extension, not standard IEEE 802.3ah). */
} epon_encryption_mode_t;

/**
 * @brief EPON operational configuration
 * 
 */
typedef struct {
    char mode[EPON_HAL_MODE_LEN];                       /**< Operational mode (e.g., "1G-EPON", "10G-EPON"). */
    epon_encryption_mode_t encryption;   /**< Current encryption mode. */
} epon_hal_link_info_t;

typedef struct {
    uint32_t interface_count;               /**< Number of active interfaces. */
    char interface_name[EPON_HAL_MAX_INTERFACES][EPON_HAL_INTERFACE_NAME_LEN]; /**< Array of interface names (e.g., "veip0", "veip1"). */
} epon_interface_list_t;


typedef struct {
    uint32_t struct_size;        /**< Size of this structure - MUST be set by caller to sizeof(epon_hal_config_t) */
    bool dpoe_supported; /**< Indicates if DPoE (DOCSIS Provisioning of EPON) is supported. */

    /**< Callback function invoked when ONU status changes. */
    void (*status_callback)(epon_onu_status_t status);
    
    /**< Callback function invoked when an alarm is raised or cleared. */
    void (*alarm_callback)(epon_hal_alarm_t alarm, bool is_active);
    
    void *reserved[4];               /**< Reserved for future callbacks - must be NULL. */
}epon_hal_config_t;

/**
 * @brief Get EPON HAL API version.
 *
 * This function returns the API version of the HAL implementation.
 * Applications should call this at initialization to verify ABI compatibility.
 *
 * @return uint32_t API version in format 0xMMmmpppp (Major.Minor.Patch)
 *
 * Example usage:
 * @code
 * uint32_t version = epon_hal_get_version();
 * if ((version >> 24) != (EPON_HAL_API_VERSION >> 24)) {
 *     // Major version mismatch - incompatible!
 *     fprintf(stderr, "EPON HAL version mismatch!\n");
 *     exit(1);
 * }
 * @endcode
 */
uint32_t epon_hal_get_version(void);

/**
 * @brief Initialize the EPON HAL module.
 *
 * This function initializes the EPON Hardware Abstraction Layer with the
 * provided configuration. It must be called before any other EPON HAL functions.
 * The function sets up callback handlers, configures DPoE support if enabled,
 * and initializes the interface mapping.
 *
 * @param[in] config Pointer to epon_hal_config_t structure containing initialization parameters.
 *                   Must not be NULL. Caller MUST set config->struct_size = sizeof(epon_hal_config_t).
 *                   The structure includes:
 *                   - DPoE support flag
 *                   - Status change callback
 *                   - Alarm callback
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS HAL initialized successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM config is NULL, struct_size is invalid, or contains invalid values.
 * @retval EPON_HAL_ERROR_HW_FAILURE Hardware initialization failed.
 * @retval EPON_HAL_ERROR_CALLBACK_REG Callback registration failed.
 * 
 */
int epon_hal_init(const epon_hal_config_t *config);

/**
 * @brief Retrieve EPON link statistics.
 *
 * This function retrieves the current EPON link statistics including frames,
 * bytes, FEC errors, and BER measurements.
 *
 * @param[in,out] stats Pointer to epon_hal_link_stats_t structure to be filled with statistics.
 *                      Caller MUST set stats->struct_size = sizeof(epon_hal_link_stats_t) before calling.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Statistics retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM stats is NULL or struct_size is invalid.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * 
 * Example usage:
 * @code
 * epon_hal_link_stats_t stats = {0};
 * stats.struct_size = sizeof(stats);
 * if (epon_hal_get_link_stats(&stats) == EPON_HAL_SUCCESS) {
 *     printf("Packets sent: %lu\n", stats.packets_sent);
 * }
 * @endcode
 */
int epon_hal_get_link_stats(epon_hal_link_stats_t *stats);

/**
 * @brief Retrieve transceiver (optical) statistics.
 *
 * This function retrieves the current transceiver statistics including optical
 * power levels, laser bias current, temperature, and supply voltage.
 *
 * @param[in,out] stats Pointer to epon_hal_transceiver_stats_t structure to be filled with statistics.
 *                      Caller MUST set stats->struct_size = sizeof(epon_hal_transceiver_stats_t) before calling.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Statistics retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM stats is NULL or struct_size is invalid.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_NOT_SUPPORTED Transceiver statistics not available.
 */
int epon_hal_get_transceiver_stats(epon_hal_transceiver_stats_t *stats);

/**
 * @brief Retrieve LLID list information.
 *
 * This function retrieves the Logical Link Identifier (LLID) list containing
 * information about all configured LLIDs and their states.
 *
 * @param[in,out] llid_list Pointer to epon_llid_list_t structure to be filled with LLID information.
 *                          The HAL implementation will allocate llid_list array and set struct_size for each element.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS LLID information retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM llid_list is NULL or struct_size is invalid.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 *
 * @note The HAL implementation allocates memory for the llid_list array 
 *       field in each epon_llid_info_t element. Caller should free this memory when done.
 * 
 */
int epon_hal_get_llid_info(epon_llid_list_t *llid_list);


/**
 * @brief Retrieve ONU manufacturer information.
 *
 * This function retrieves the manufacturer details of the ONU including
 * manufacturer name, model number, hardware/firmware versions, serial number,
 * and vendor OUI as per IEEE 802.3ah specifications.
 *
 * @param[in,out] info Pointer to epon_onu_manufacturer_info_t structure to be filled with manufacturer information.
 *                     Caller MUST set info->struct_size = sizeof(epon_onu_manufacturer_info_t) before calling.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Manufacturer information retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM info is NULL or struct_size is invalid.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 */
int epon_hal_get_manufacturer_info(epon_onu_manufacturer_info_t *info);

/**
 * @brief Clear EPON HAL statistics counters.
 *
 * This function resets all EPON link statistics counters to zero, including
 * frame counts, byte counts, FEC error counters, and MAC reset counters.
 * Optical power measurements are not affected.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Statistics cleared successfully.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_HW_FAILURE Hardware operation failed.
 */
int epon_hal_clear_stats(void);

/**
 * @brief Reset the ONU and restart registration process.
 *
 * This function resets the ONU and initiates the registration process with the OLT.
 * The ONU will deregister, perform a soft reset, and attempt to re-register
 * following the MPCP discovery and registration procedure.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS ONU reset initiated successfully.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_HW_FAILURE Reset operation failed.
 *
 * @note This operation will cause temporary service disruption.
 */
int epon_hal_reset_onu(void);

/**
 * @brief Perform factory reset of HAL configuration.
 *
 * This function resets the EPON HAL configuration to factory defaults.
 * This includes clearing all custom settings, statistics, and restoring
 * default operational parameters. The ONU will need to be reconfigured
 * and re-initialized after this operation.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Factory reset completed successfully.
 * @retval EPON_HAL_ERROR_HW_FAILURE Factory reset failed.
 * @retval EPON_HAL_ERROR_CONFIG Unable to restore default configuration.
 *
 * @note This operation will cause service disruption and loss of all configuration.
 *       Re-initialization with epon_hal_init() is required after factory reset.
 */
int epon_hal_factory_reset(void);

/**
 * @brief Get current EPON link information.
 *
 * This function retrieves the current EPON link information including
 * operational mode (1G-EPON or 10G-EPON) and encryption mode negotiated with the OLT.
 *
 * @param[out] info Pointer to epon_hal_link_info_t structure to be filled with link information.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Link information retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM info is NULL.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 */
int epon_hal_get_link_info(epon_hal_link_info_t *info);

/**
 * @brief Retrieve interface list information.
 *
 * This function retrieves the list of interface names (S1/IP interfaces)
 * configured by the OLT. Multiple interfaces may be created, each potentially
 * associated with different VLANs or service instances.
 *
 * @param[out] if_list Pointer to epon_interface_list_t structure to be filled with interface names.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS Interface information retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM if_list is NULL.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 *
 * @note The ONU status EPON_ONU_STATUS_LINK_UP is sent only after all configured
 *       interfaces are operational.
 */
int epon_hal_get_interface_list(epon_interface_list_t *if_list);

/**
 * @brief Enable or disable logging of specific OAM messages.
 *
 * This function configures which OAM message types should be logged by the HAL.
 * OAM messages matching the enabled bitmask will be logged using the configured
 * HAL_LOG_FUNCTION at DEBUG or TRACE level as per IEEE 802.3ah specification.
 *
 * @param[in] oam_log_mask Bitmask of OAM message types to enable logging.
 *                         Use epon_oam_log_type_t values combined with bitwise OR.
 *                         Use EPON_OAM_LOG_ALL to enable all OAM message logging.
 *                         Use 0 to disable all OAM message logging.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS OAM logging configuration updated successfully.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_NOT_SUPPORTED OAM logging not supported by implementation.
 *
 * @note This function only controls which OAM messages are logged, not whether
 *       they are processed. All OAM messages are always processed regardless of
 *       this logging configuration.
 * @note The actual logging output depends on HAL_LOG_FUNCTION implementation.
 *       If HAL_LOG_FUNCTION is not defined, no output will be produced.
 *
 * Example usage:
 * @code
 * // Enable logging for OAM Info and Event messages only
 * uint32_t mask = EPON_OAM_LOG_INFO | EPON_OAM_LOG_EVENT;
 * epon_hal_set_oam_log_mask(mask);
 *
 * // Enable all OAM message logging
 * epon_hal_set_oam_log_mask(EPON_OAM_LOG_ALL);
 *
 * // Disable all OAM message logging
 * epon_hal_set_oam_log_mask(0);
 * @endcode
 */
int epon_hal_set_oam_log_mask(uint32_t oam_log_mask);


/* ============================================================================
 * DPoE (DOCSIS Provisioning of EPON) Extension APIs
 * Enable with -DEPON_HAL_DPOE_SUPPORT at compile time
 * ============================================================================ */
#ifdef EPON_HAL_DPOE_SUPPORT

/**
 * @brief CPE MAC address entry type
 */
typedef enum {
    DPOE_CPE_MAC_STATIC = 0,       /**< Statically configured CPE MAC address. */
    DPOE_CPE_MAC_DYNAMIC = 1       /**< Dynamically learned CPE MAC address. */
} dpoe_cpe_mac_type_t;

/**
 * @brief CPE MAC address entry information
 * 
 */
typedef struct {
    uint8_t mac_address[EPON_HAL_MAC_ADDR_LEN]; /**< CPE MAC address. */
    dpoe_cpe_mac_type_t type;      /**< Type: static or dynamic. */
    uint32_t age_time;             /**< Age time in seconds (0 for static entries). */
} dpoe_cpe_mac_entry_t;

/**
 * @brief CPE MAC address table
 */
typedef struct {
    uint32_t max_cpe;        /**< Maximum number of CPE entries supported. */
    uint32_t static_cpe_count;     /**< Number of static CPE entries. */
    uint32_t dynamic_cpe_count;    /**< Number of dynamically learned CPE entries. */
    dpoe_cpe_mac_entry_t *cpe_list; /**< Pointer to array of CPE MAC entries. */
} dpoe_cpe_mac_table_t;

/**
 * @brief Get DPoE system descriptor information.
 *
 * This function retrieves the DPoE system descriptor information as per
 * the DPoE specification.
 *
 * @param[out] sys_desc Pointer to character buffer to be filled with system descriptor string.
 * @param[in] desc_len Length of the sys_desc buffer.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS System descriptor retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM sys_desc is NULL or desc_len is insufficient.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_NOT_SUPPORTED DPoE not supported.
 */
int dpoe_hal_get_sys_descriptor(char *sys_desc, uint32_t desc_len);

/**
 * @brief Retrieve CPE MAC address table.
 *
 * This function retrieves the complete CPE MAC address table including both
 * statically configured and dynamically learned CPE MAC addresses.
 *
 * @param[out] cpe_table Pointer to dpoe_cpe_mac_table_t structure to be filled with CPE MAC information.
 *
 * @return epon_hal_return_t status code.
 * @retval EPON_HAL_SUCCESS CPE MAC table retrieved successfully.
 * @retval EPON_HAL_ERROR_INVALID_PARAM cpe_table is NULL.
 * @retval EPON_HAL_ERROR_NOT_INITIALIZED HAL not initialized.
 * @retval EPON_HAL_ERROR_NOT_SUPPORTED DPoE not supported.
 *
 * @note The HAL implementation allocates memory for the cpe_list array. Caller should free this memory when done.
 */
int dpoe_hal_get_cpe_mac_table(dpoe_cpe_mac_table_t *cpe_table);

#endif /* EPON_HAL_DPOE_SUPPORT */


#ifdef __cplusplus
}
#endif

#endif /* _EPON_HAL_H_ */

