# Enhanced Password Search Feature

CamSniff now includes comprehensive password wordlists and enhanced authentication testing capabilities.

## New Features

### Password and Username Wordlists

- **Location**: `data/passwords.txt` and `data/usernames.txt`
- **Content**: Camera-specific passwords and usernames including brand-specific defaults
- **Size**: 95 passwords and 65 usernames covering major camera brands and common patterns

### Configuration Options

Add these to your `camcfg.json`:

```json
{
  "password_wordlist": "data/passwords.txt",
  "username_wordlist": "data/usernames.txt"
}
```

### Enhanced Authentication Testing

The tool now automatically:

1. **RTSP Authentication**: Uses comprehensive wordlists for RTSP brute force attacks
2. **HTTP Authentication**: Generates smart credential combinations for HTTP testing
3. **Quick Discovery**: Uses top combinations for fast initial testing
4. **Fallback Support**: Falls back to built-in credentials if wordlists are unavailable

### Brand-Specific Passwords

Includes passwords for major camera brands:
- Hikvision
- Dahua  
- Axis
- Foscam
- Vivotek
- Amcrest
- Reolink
- Uniview
- Bosch
- And many more

### Customization

You can provide your own wordlists by:

1. Setting `HYDRA_USER_FILE` and `HYDRA_PASS_FILE` environment variables
2. Setting `HYDRA_COMBO_FILE` for custom username:password combinations
3. Modifying the wordlist files in the `data/` directory
4. Updating the configuration file with different wordlist paths

### Performance Optimizations

- Uses top 5 usernames × top 8 passwords for quick HTTP testing
- Limits Hydra attacks to prevent excessive testing
- Smart fallback to hardcoded credentials when wordlists fail
- Supports empty credentials for open endpoints