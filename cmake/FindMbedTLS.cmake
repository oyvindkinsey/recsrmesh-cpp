# FindMbedTLS - locate Mbed TLS headers and libraries.
# Provides MBEDTLS_INCLUDE_DIRS, MBEDTLS_LIBRARIES and imported targets
# MbedTLS::mbedtls, MbedTLS::mbedcrypto, MbedTLS::mbedx509.
find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/aes.h)
find_library(MBEDTLS_LIBRARY NAMES mbedtls)
find_library(MBEDCRYPTO_LIBRARY NAMES mbedcrypto)
find_library(MBEDX509_LIBRARY NAMES mbedx509)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDCRYPTO_LIBRARY MBEDX509_LIBRARY)

if(MbedTLS_FOUND)
    set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
    foreach(comp mbedtls mbedcrypto mbedx509)
        if(NOT TARGET MbedTLS::${comp})
            add_library(MbedTLS::${comp} UNKNOWN IMPORTED)
        endif()
    endforeach()
    set_target_properties(MbedTLS::mbedtls PROPERTIES
        IMPORTED_LOCATION ${MBEDTLS_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
        IMPORTED_LOCATION ${MBEDCRYPTO_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
    set_target_properties(MbedTLS::mbedx509 PROPERTIES
        IMPORTED_LOCATION ${MBEDX509_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_INCLUDE_DIR})
endif()
mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDCRYPTO_LIBRARY MBEDX509_LIBRARY)
