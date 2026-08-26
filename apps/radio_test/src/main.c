/*
 * Radio bring-up test for LPSTK-CC1352R.
 *
 * Purpose: determine whether the CC1352R radio can be started at all on this
 * board. TI's LaunchPad sniffer firmware blocked forever inside CMD_FS waiting
 * for the synthesiser to lock, with no fault and no interrupt. If Zephyr's
 * driver starts the radio here, the silicon is fine and TI's firmware was
 * simply built for the wrong board. If this stalls in the same place, the
 * fault is in hardware.
 *
 * Each step prints BEFORE it runs, so a stall is visible by what is missing.
 */
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/sys/printk.h>

static const struct device *const radio_dev =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));

static void print_caps(enum ieee802154_hw_caps caps)
{
	printk("capabilities = 0x%08x\n", (unsigned int)caps);
	printk("  ENERGY_SCAN     %c\n", (caps & IEEE802154_HW_ENERGY_SCAN)    ? 'y' : 'n');
	printk("  FCS             %c\n", (caps & IEEE802154_HW_FCS)            ? 'y' : 'n');
	printk("  FILTER          %c\n", (caps & IEEE802154_HW_FILTER)         ? 'y' : 'n');
	printk("  PROMISC         %c  <- needed for sniffing\n",
	                                 (caps & IEEE802154_HW_PROMISC)        ? 'y' : 'n');
	printk("  CSMA            %c\n", (caps & IEEE802154_HW_CSMA)           ? 'y' : 'n');
	printk("  TX_RX_ACK       %c\n", (caps & IEEE802154_HW_TX_RX_ACK)      ? 'y' : 'n');
}

int main(void)
{
	struct ieee802154_radio_api *api;
	int ret;

	printk("\n\n=== LPSTK-CC1352R radio bring-up test ===\n");
	printk("board: %s\n", CONFIG_BOARD);

	printk("[1] checking device readiness...\n");
	if (!device_is_ready(radio_dev)) {
		printk("    FAIL: radio device not ready\n");
		return 0;
	}
	printk("    OK: %s\n", radio_dev->name);

	api = (struct ieee802154_radio_api *)radio_dev->api;

	printk("[2] reading capabilities...\n");
	print_caps(api->get_capabilities(radio_dev));

	printk("[3] set_channel(11)... (2405 MHz)\n");
	ret = api->set_channel(radio_dev, 11);
	printk("    -> %d %s\n", ret, ret == 0 ? "OK" : "FAILED");

	/* This is the step that hung under TI's firmware. If the next line
	 * never appears, the synthesiser failed to lock again. */
	printk("[4] start() -- THIS is where TI's firmware hung...\n");
	ret = api->start(radio_dev);
	printk("    -> %d %s\n", ret, ret == 0 ? "OK -- RADIO IS RUNNING" : "FAILED");

	if (ret == 0) {
		printk("\n*** RADIO STARTED. Hardware is good. ***\n");
	}

	for (int i = 0;; i++) {
		k_sleep(K_SECONDS(5));
		printk("alive %d (radio %s)\n", i, ret == 0 ? "running" : "stopped");
	}
	return 0;
}
