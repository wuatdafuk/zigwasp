/*
 * zigwasp -- IEEE 802.15.4 / Zigbee sniffer for the LPSTK-CC1352R.
 *
 * Puts the CC1352R radio into promiscuous mode (hardware address filtering and
 * auto-ACK both disabled -- see zephyr-promisc.patch) and streams every frame
 * it hears out of UART0 as length-delimited records. The host turns those into
 * PCAP for Wireshark.
 *
 * Wire format, little-endian:
 *   0xA7 0x5A   magic
 *   u8          version (1)
 *   u8          channel
 *   u8          rssi (raw; interpret as int8 dBm)
 *   u8          lqi
 *   u32         timestamp, microseconds since boot
 *   u16         payload length
 *   u8[len]     MAC frame, including FCS
 *   u8          checksum: sum of every byte after the magic, mod 256
 *
 * Host -> device commands:
 *   'C' <channel>   set channel (11..26)
 *   'P'             ping; device replies with a zero-length record
 *
 * IMPORTANT: the channel must be set through the 802.15.4 L2 management API,
 * not the raw radio API. The L2 keeps its own ctx->channel and refuses to bring
 * the interface up (-ENETDOWN) while it is IEEE802154_NO_CHANNEL -- and a down
 * interface silently drops every received frame before it reaches the
 * promiscuous queue.
 */
#include <zephyr/kernel.h>
#include <errno.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/net/ieee802154_pkt.h>
#include <zephyr/net/ieee802154_mgmt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/promiscuous.h>
#include <zephyr/sys/printk.h>
#include <zephyr/pm/policy.h>
#include <zephyr/sys/sys_io.h>

#define MAGIC0 0xA7
#define MAGIC1 0x5A
#define VERSION 1
#define DEFAULT_CHANNEL 15
#define MAX_FRAME 160

static const struct device *const uart_dev =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
static const struct device *const radio_dev =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));

static struct net_if *g_iface;
static uint8_t cur_channel = DEFAULT_CHANNEL;
static uint32_t frames_seen;
static bool promisc_ok;
static struct k_mutex tx_lock;

static void emit(const uint8_t *frame, uint16_t len, uint8_t rssi, uint8_t lqi)
{
	uint8_t hdr[10];
	uint32_t ts = k_cyc_to_us_near32(k_cycle_get_32());
	uint8_t sum = 0;

	hdr[0] = MAGIC0;  hdr[1] = MAGIC1;  hdr[2] = VERSION;
	hdr[3] = cur_channel;  hdr[4] = rssi;  hdr[5] = lqi;
	hdr[6] = ts & 0xFF;          hdr[7] = (ts >> 8) & 0xFF;
	hdr[8] = (ts >> 16) & 0xFF;  hdr[9] = (ts >> 24) & 0xFF;

	k_mutex_lock(&tx_lock, K_FOREVER);
	for (int i = 0; i < 10; i++) {
		uart_poll_out(uart_dev, hdr[i]);
	}
	for (int i = 2; i < 10; i++) {
		sum += hdr[i];
	}
	uart_poll_out(uart_dev, len & 0xFF);
	uart_poll_out(uart_dev, (len >> 8) & 0xFF);
	sum += (len & 0xFF) + ((len >> 8) & 0xFF);
	for (uint16_t i = 0; i < len; i++) {
		uart_poll_out(uart_dev, frame[i]);
		sum += frame[i];
	}
	uart_poll_out(uart_dev, sum);
	k_mutex_unlock(&tx_lock);
}

static int set_channel(uint8_t ch)
{
	uint16_t channel = ch;
	int r;

	if (ch < 11 || ch > 26) {
		return -EINVAL;
	}
	if (!g_iface) {
		return -ENODEV;
	}
	r = net_mgmt(NET_REQUEST_IEEE802154_SET_CHANNEL, g_iface,
		     &channel, sizeof(channel));
	if (r) {
		printk("zigwasp: set_channel(%u) -> %d\n", ch, r);
		return r;
	}
	cur_channel = ch;
	return 0;
}

/* AON_PMCTL:RESETCTL.SYSRESET -- what TI's SysCtrlSystemReset() writes. */
#define AON_PMCTL_RESETCTL 0x40090028
#define AON_PMCTL_SYSRESET BIT(31)

/* Quiesce the radio, then reset ourselves.
 *
 * Resetting from the debugger while the RF core is mid-reception leaves the
 * radio running underneath the reset CPU; the next boot's RF_open() then
 * inherits a live radio and TI's oscillatorISR storms on IRQ 34. That wedge
 * survives every software reset (vectreset, SYSRESETREQ, AON SYSRESET) and
 * clears only on a physical power cycle. Bringing the interface down first
 * stops the radio cleanly, so the reset starts from a sane state.
 */
static void clean_reboot(void)
{
	if (g_iface) {
		net_if_down(g_iface);
	}
	k_sleep(K_MSEC(200));
	sys_write32(AON_PMCTL_SYSRESET, AON_PMCTL_RESETCTL);
	while (1) {
		k_sleep(K_MSEC(100));
	}
}

static void cmd_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);
	uint8_t ch;
	int pending = 0;

	while (1) {
		if (uart_poll_in(uart_dev, &ch) == 0) {
			if (pending == 'C') {
				set_channel(ch);
				pending = 0;
			} else if (ch == 'C') {
				pending = 'C';
			} else if (ch == 'P') {
				emit(NULL, 0, 0, 0);
				pending = 0;
			} else if (ch == 'R') {
				clean_reboot();
			} else if (ch == 'Q') {
				/* Quiesce: stop the radio and park, so the
				 * debugger can halt and reflash without leaving
				 * a live RF core under the reset CPU.
				 */
				if (g_iface) {
					net_if_down(g_iface);
				}
				emit(NULL, 0, 0, 0);
				pending = 0;
			}
		} else {
			k_sleep(K_MSEC(10));
		}
	}
}
K_THREAD_DEFINE(cmd_tid, 1024, cmd_thread, NULL, NULL, NULL, 7, 0, 0);

int main(void)
{
	struct ieee802154_radio_api *api;
	struct ieee802154_config cfg;
	uint8_t buf[MAX_FRAME];

	k_mutex_init(&tx_lock);

	/* Forbid deep standby for the lifetime of the app.
	 *
	 * The SoC Kconfig does "select PM", so CONFIG_PM cannot be turned off
	 * from prj.conf -- we have to block the state at runtime instead.
	 * Standby powers down XOSC_HF; a disturbed standby/wake transition (a
	 * JTAG halt landing in one, for instance) wedges the oscillator state
	 * machine and TI's oscillatorISR then storms on IRQ 34 forever. That
	 * wedge survives both a warm reset and an AON_PMCTL SYSRESET, and used
	 * to need a physical power cycle to clear. A sniffer has to listen
	 * continuously anyway, so standby costs us nothing.
	 */
	pm_policy_state_lock_get(PM_STATE_STANDBY, PM_ALL_SUBSTATES);

	printk("\nzigwasp sniffer starting (standby locked out)\n");

	if (!device_is_ready(radio_dev) || !device_is_ready(uart_dev)) {
		printk("zigwasp: device not ready\n");
		return 0;
	}
	api = (struct ieee802154_radio_api *)radio_dev->api;

	g_iface = net_if_get_first_by_type(&NET_L2_GET_NAME(IEEE802154));
	if (!g_iface) {
		printk("zigwasp: no 802.15.4 iface\n");
		return 0;
	}

	{
		enum ieee802154_hw_caps caps = api->get_capabilities(radio_dev);
		enum net_l2_flags lf = net_if_l2(g_iface)->get_flags(g_iface);

		printk("zigwasp: radio caps=0x%08x HW_PROMISC=%d\n",
		       (unsigned int)caps, !!(caps & IEEE802154_HW_PROMISC));
		printk("zigwasp: l2 flags=0x%08x L2_PROMISC=%d\n",
		       (unsigned int)lf, !!(lf & NET_L2_PROMISC_MODE));
	}

	while (!promisc_ok) {
		/* Channel first: the L2 will not come up without one. */
		if (set_channel(cur_channel) != 0) {
			k_sleep(K_SECONDS(2));
			continue;
		}

		if (!net_if_is_up(g_iface)) {
			int r = net_if_up(g_iface);

			if (r < 0 && r != -EINPROGRESS) {
				printk("zigwasp: net_if_up -> %d\n", r);
			}
			for (int i = 0; i < 100 && !net_if_is_up(g_iface); i++) {
				k_sleep(K_MSEC(50));
			}
		}
		if (!net_if_is_up(g_iface)) {
			printk("zigwasp: iface still down, retrying\n");
			k_sleep(K_SECONDS(2));
			continue;
		}

		/* Promiscuous at the radio: no address filter, no auto-ACK. */
		cfg.promiscuous = true;
		if (api->configure(radio_dev, IEEE802154_CONFIG_PROMISCUOUS,
				   &cfg) != 0) {
			printk("zigwasp: radio promiscuous config failed\n");
		}

		int r = net_promisc_mode_on(g_iface);

		if (r == 0 || r == -EALREADY) {
			promisc_ok = true;
			break;
		}
		printk("zigwasp: promisc_mode_on -> %d\n", r);
		k_sleep(K_SECONDS(2));
	}

	printk("zigwasp ready: ch=%u promisc=%d iface_up=%d\n",
	       cur_channel, promisc_ok, net_if_is_up(g_iface));

	while (1) {
		struct net_pkt *pkt = net_promisc_mode_wait_data(K_MSEC(5000));
		size_t len;

		if (!pkt) {
			printk("zigwasp: alive frames=%u ch=%u\n",
			       frames_seen, cur_channel);
			continue;
		}
		frames_seen++;

		len = net_pkt_get_len(pkt);
		if (len > 0 && len <= sizeof(buf)) {
			net_pkt_cursor_init(pkt);
			if (net_pkt_read(pkt, buf, len) == 0) {
				/* The driver sets RSSI via
				 * net_pkt_set_ieee802154_rssi_dbm(), so read
				 * the dBm accessor -- net_pkt_ieee802154_rssi()
				 * returns a normalised 0..255 value instead.
				 */
				emit(buf, (uint16_t)len,
				     (uint8_t)net_pkt_ieee802154_rssi_dbm(pkt),
				     net_pkt_ieee802154_lqi(pkt));
			}
		}
		net_pkt_unref(pkt);
	}
	return 0;
}
