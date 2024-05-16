# Deauth-attack

### Syntax  
```
syntax : deauth <interface> <ap_mac> [<station_mac> [-auth]]  
sample : deauth mon0 00:11:22:33:44:55 66:77:88:99:AA:BB
```


## RadioTap Header  
- IEEE에서 제공하는 RadioTap Header구조
```
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));
```
