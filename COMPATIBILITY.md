# GNU Radio Forward Compatibility

This document describes the forward compatibility strategy for gr-linux-crypto with future GNU Radio versions.

## Version Requirements

- **Minimum Version**: GNU Radio 3.10.12.0
- **Tested Versions**: 3.10.12.0
- **Future Compatibility**: The codebase is designed to be compatible with future GNU Radio versions

## Compatibility Strategy

### 1. API Usage

The codebase uses stable GNU Radio APIs that are part of the long-term supported API:

- `gr::sync_block` - Core block base class (stable since 3.7)
- `gr::io_signature` - I/O signature handling (stable since 3.7)
- `gnuradio::get_initial_sptr` - Smart pointer factory (stable since 3.7)
- `__GR_ATTR_EXPORT` / `__GR_ATTR_IMPORT` - Symbol visibility macros (stable)

### 2. Version Checking

The CMake configuration:
- Enforces a minimum version requirement (3.10.12.0)
- Does NOT block future versions
- Uses `VERSION_LESS` which allows any version >= minimum

### 3. Python Bindings

Python bindings use:
- `pybind11` - Standard GNU Radio binding approach
- Standard GNU Radio block inheritance patterns
- No version-specific code

### 4. Library Versioning

The library uses GNU Radio's versioning scheme:
- `VERSION ${GNURADIO_VERSION}` - Tracks GNU Radio version
- `SOVERSION ${GNURADIO_SOVERSION}` - Uses GNU Radio's SO version

This ensures ABI compatibility with the GNU Radio version it was built against.

## Testing with Future Versions

When testing with new GNU Radio versions:

1. **Build Test**: Ensure the module builds without errors
2. **Runtime Test**: Verify blocks work correctly
3. **API Check**: Check for any deprecation warnings
4. **Update Minimum**: If new features are needed, update minimum version requirement

## Known Compatibility Notes

- **GNU Radio 3.10.x**: Fully supported (3.10.12.0+)
- **GNU Radio 3.11.x**: Should work (not yet tested)
- **GNU Radio 4.x**: May require updates if API changes occur

## Reporting Compatibility Issues

If you encounter issues with a future GNU Radio version:

1. Check the GNU Radio release notes for API changes
2. Review deprecation warnings during build
3. Test with the minimum supported version to isolate issues
4. Report issues with GNU Radio version and error details

## Maintenance

This compatibility document should be updated when:
- New GNU Radio versions are tested
- Minimum version requirements change
- API deprecations affect the codebase
