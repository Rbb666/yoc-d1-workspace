/* conn.c - Bluetooth connection handling */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ble_os.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <atomic.h>
#include <misc/byteorder.h>
#include <misc/util.h>
#include <misc/slist.h>
#include <misc/stack.h>
#include <misc/__assert.h>

#include <bluetooth/hci.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/hci_driver.h>
#include <bluetooth/att.h>

#define BT_DBG_ENABLED IS_ENABLED(CONFIG_BT_DEBUG_CONN)
#define LOG_MODULE_NAME bt_conn
#include "common/log.h"
#include <common/common.h>
#include "hci_core.h"
#include "conn_internal.h"
#include "l2cap_internal.h"
#include "keys.h"
#include "smp.h"
#include "att_internal.h"
#include "gatt_internal.h"
#include <hci_api.h>

struct tx_meta {
	struct bt_conn_tx *tx;
};

#define tx_data(buf) ((struct tx_meta *)net_buf_user_data(buf))

NET_BUF_POOL_DEFINE(acl_tx_pool, CONFIG_BT_L2CAP_TX_BUF_COUNT,
		    BT_L2CAP_BUF_SIZE(CONFIG_BT_L2CAP_TX_MTU),
		    sizeof(struct tx_meta), NULL);

#if CONFIG_BT_L2CAP_TX_FRAG_COUNT > 0

#if defined(CONFIG_BT_CTLR_TX_BUFFER_SIZE)
#define FRAG_SIZE BT_L2CAP_BUF_SIZE(CONFIG_BT_CTLR_TX_BUFFER_SIZE - 4)
#else
#define FRAG_SIZE BT_L2CAP_BUF_SIZE(CONFIG_BT_L2CAP_TX_MTU)
#endif

/* Dedicated pool for fragment buffers in case queued up TX buffers don't
 * fit the controllers buffer size. We can't use the acl_tx_pool for the
 * fragmentation, since it's possible that pool is empty and all buffers
 * are queued up in the TX queue. In such a situation, trying to allocate
 * another buffer from the acl_tx_pool would result in a deadlock.
 */
NET_BUF_POOL_FIXED_DEFINE(frag_pool, CONFIG_BT_L2CAP_TX_FRAG_COUNT, FRAG_SIZE,
			  NULL);

#endif /* CONFIG_BT_L2CAP_TX_FRAG_COUNT > 0 */

#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_BREDR)
const struct bt_conn_auth_cb *bt_auth;
#endif /* CONFIG_BT_SMP || CONFIG_BT_BREDR */

static struct bt_conn conns[CONFIG_BT_MAX_CONN];
static struct bt_conn_cb *callback_list;

static struct bt_conn_tx conn_tx[CONFIG_BT_CONN_TX_MAX];
struct kfifo free_tx;

#if defined(CONFIG_BT_BREDR)
static struct bt_conn sco_conns[CONFIG_BT_MAX_SCO_CONN];

enum pairing_method {
	LEGACY,			/* Legacy (pre-SSP) pairing */
	JUST_WORKS,		/* JustWorks pairing */
	PASSKEY_INPUT,		/* Passkey Entry input */
	PASSKEY_DISPLAY,	/* Passkey Entry display */
	PASSKEY_CONFIRM,	/* Passkey confirm */
};

/* based on table 5.7, Core Spec 4.2, Vol.3 Part C, 5.2.2.6 */
static const u8_t ssp_method[4 /* remote */][4 /* local */] = {
	      { JUST_WORKS, JUST_WORKS, PASSKEY_INPUT, JUST_WORKS },
	      { JUST_WORKS, PASSKEY_CONFIRM, PASSKEY_INPUT, JUST_WORKS },
	      { PASSKEY_DISPLAY, PASSKEY_DISPLAY, PASSKEY_INPUT, JUST_WORKS },
	      { JUST_WORKS, JUST_WORKS, JUST_WORKS, JUST_WORKS },
};
#endif /* CONFIG_BT_BREDR */
#if !(defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE)
struct k_sem *bt_conn_get_pkts(struct bt_conn *conn)
{
#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR || !bt_dev.le.mtu) {
		return &bt_dev.br.pkts;
	}
#endif /* CONFIG_BT_BREDR */

	return &bt_dev.le.pkts;
}
#endif
static inline const char *state2str(bt_conn_state_t state)
{
	switch (state) {
	case BT_CONN_DISCONNECTED:
		return "disconnected";
	case BT_CONN_CONNECT_SCAN:
		return "connect-scan";
	case BT_CONN_CONNECT_DIR_ADV:
		return "connect-dir-adv";
	case BT_CONN_CONNECT_ADV:
		return "connect-adv";
	case BT_CONN_CONNECT_AUTO:
		return "connect-auto";
	case BT_CONN_CONNECT:
		return "connect";
	case BT_CONN_CONNECTED:
		return "connected";
	case BT_CONN_DISCONNECT:
		return "disconnect";
	default:
		return "(unknown)";
	}
}

static void notify_connected(struct bt_conn *conn)
{
	struct bt_conn_cb *cb;

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->connected) {
			cb->connected(conn, conn->err);
		}
	}

	if (!conn->err) {
		bt_gatt_connected(conn);
	}
}

static void notify_disconnected(struct bt_conn *conn)
{
	struct bt_conn_cb *cb;

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->disconnected) {
			cb->disconnected(conn, conn->err);
		}
	}
}

#if defined(CONFIG_BT_REMOTE_INFO)
void notify_remote_info(struct bt_conn *conn)
{
	struct bt_conn_remote_info remote_info;
	struct bt_conn_cb *cb;
	int err;

	err = bt_conn_get_remote_info(conn, &remote_info);
	if (err) {
		BT_DBG("Notify remote info failed %d", err);
		return;
	}

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->remote_info_available) {
			cb->remote_info_available(conn, &remote_info);
		}
	}
}
#endif /* defined(CONFIG_BT_REMOTE_INFO) */

void notify_le_param_updated(struct bt_conn *conn)
{
	struct bt_conn_cb *cb;

	/* If new connection parameters meet requirement of pending
	 * parameters don't send slave conn param request anymore on timeout
	 */
	if (atomic_test_bit(conn->flags, BT_CONN_SLAVE_PARAM_SET) &&
	    conn->le.interval >= conn->le.interval_min &&
	    conn->le.interval <= conn->le.interval_max &&
	    conn->le.latency == conn->le.pending_latency &&
	    conn->le.timeout == conn->le.pending_timeout) {
		atomic_clear_bit(conn->flags, BT_CONN_SLAVE_PARAM_SET);
	}

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->le_param_updated) {
			cb->le_param_updated(conn, conn->le.interval,
					     conn->le.latency,
					     conn->le.timeout);
		}
	}
}

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
void notify_le_data_len_updated(struct bt_conn *conn)
{
	struct bt_conn_cb *cb;

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->le_data_len_updated) {
			cb->le_data_len_updated(conn, &conn->le.data_len);
		}
	}
}
#endif

#if defined(CONFIG_BT_USER_PHY_UPDATE)
void notify_le_phy_updated(struct bt_conn *conn)
{
	struct bt_conn_cb *cb;

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->le_phy_updated) {
			cb->le_phy_updated(conn, &conn->le.phy);
		}
	}
}
#endif

bool le_param_req(struct bt_conn *conn, struct bt_le_conn_param *param)
{
	struct bt_conn_cb *cb;

	if (!bt_le_conn_params_valid(param)) {
		return false;
	}

	for (cb = callback_list; cb; cb = cb->_next) {
		if (!cb->le_param_req) {
			continue;
		}

		if (!cb->le_param_req(conn, param)) {
			return false;
		}

		/* The callback may modify the parameters so we need to
		 * double-check that it returned valid parameters.
		 */
		if (!bt_le_conn_params_valid(param)) {
			return false;
		}
	}

	/* Default to accepting if there's no app callback */
	return true;
}

static int send_conn_le_param_update(struct bt_conn *conn,
				const struct bt_le_conn_param *param)
{
	BT_DBG("conn %p features 0x%02x params (%d-%d %d %d)", conn,
	       conn->le.features[0], param->interval_min,
	       param->interval_max, param->latency, param->timeout);

	/* Proceed only if connection parameters contains valid values*/
	if (!bt_le_conn_params_valid(param)) {
		return -EINVAL;
	}

	/* Use LE connection parameter request if both local and remote support
	 * it; or if local role is master then use LE connection update.
	 */
	if ((BT_FEAT_LE_CONN_PARAM_REQ_PROC(bt_dev.le.features) &&
	     BT_FEAT_LE_CONN_PARAM_REQ_PROC(conn->le.features) &&
	     !atomic_test_bit(conn->flags, BT_CONN_SLAVE_PARAM_L2CAP)) ||
	     (conn->role == BT_HCI_ROLE_MASTER)) {
		int rc;

		rc = bt_conn_le_conn_update(conn, param);

		/* store those in case of fallback to L2CAP */
		if (rc == 0) {
			conn->le.pending_latency = param->latency;
			conn->le.pending_timeout = param->timeout;
		}

		return rc;
	}

	/* If remote master does not support LL Connection Parameters Request
	 * Procedure
	 */
	return bt_l2cap_update_conn_param(conn, param);
}

static void tx_free(struct bt_conn_tx *tx)
{
	tx->cb = NULL;
	tx->user_data = NULL;
	tx->pending_no_cb = 0U;
	k_fifo_put(&free_tx, tx);
}

static void tx_notify(struct bt_conn *conn)
{
	BT_DBG("conn %p", conn);

	while (1) {
		struct bt_conn_tx *tx;
		unsigned int key;
		bt_conn_tx_cb_t cb;
		void *user_data;

		key = irq_lock();
		if (sys_slist_is_empty(&conn->tx_complete)) {
			irq_unlock(key);
			break;
		}

		tx = (void *)sys_slist_get_not_empty(&conn->tx_complete);
		irq_unlock(key);

		BT_DBG("tx %p cb %p user_data %p", tx, tx->cb, tx->user_data);

		/* Copy over the params */
		cb = tx->cb;
		user_data = tx->user_data;

		/* Free up TX notify since there may be user waiting */
		tx_free(tx);

		/* Run the callback, at this point it should be safe to
		 * allocate new buffers since the TX should have been
		 * unblocked by tx_free.
		 */
		cb(conn, user_data);
	}
}

static void tx_complete_work(struct k_work *work)
{
	struct bt_conn *conn = CONTAINER_OF(work, struct bt_conn,
					   tx_complete_work);

	BT_DBG("conn %p", conn);
	tx_notify(conn);
}

static void conn_update_timeout(struct k_work *work)
{
	struct bt_conn *conn = CONTAINER_OF(work, struct bt_conn, update_work);
	const struct bt_le_conn_param *param;

	BT_DBG("conn %p", conn);

	if (conn->state == BT_CONN_DISCONNECTED) {
		bt_l2cap_disconnected(conn);
		notify_disconnected(conn);

		/* Release the reference we took for the very first
		 * state transition.
		 */
		bt_conn_unref(conn);

		/* A new reference likely to have been released here,
		 * Resume advertising.
		 */
		if (IS_ENABLED(CONFIG_BT_PERIPHERAL)) {
			bt_le_adv_resume();
		}

		return;
	}

	if (conn->type != BT_CONN_TYPE_LE) {
		return;
	}

	if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
	    conn->role == BT_CONN_ROLE_MASTER) {
		/* we don't call bt_conn_disconnect as it would also clear
		 * auto connect flag if it was set, instead just cancel
		 * connection directly
		 */
		bt_le_create_conn_cancel();
		return;
	}

	if (IS_ENABLED(CONFIG_BT_GAP_AUTO_UPDATE_CONN_PARAMS)) {
		/* if application set own params use those, otherwise
		 * use defaults.
		 */
		if (atomic_test_and_clear_bit(conn->flags,
					      BT_CONN_SLAVE_PARAM_SET)) {
			param = BT_LE_CONN_PARAM(conn->le.interval_min,
						conn->le.interval_max,
						conn->le.pending_latency,
						conn->le.pending_timeout);
			send_conn_le_param_update(conn, param);
		} else {
#if defined(CONFIG_BT_GAP_PERIPHERAL_PREF_PARAMS)
			param = BT_LE_CONN_PARAM(
					CONFIG_BT_PERIPHERAL_PREF_MIN_INT,
					CONFIG_BT_PERIPHERAL_PREF_MAX_INT,
					CONFIG_BT_PERIPHERAL_PREF_SLAVE_LATENCY,
					CONFIG_BT_PERIPHERAL_PREF_TIMEOUT);
			send_conn_le_param_update(conn, param);
#endif
		}
	}

	atomic_set_bit(conn->flags, BT_CONN_SLAVE_PARAM_UPDATE);
}

static struct bt_conn *conn_new(void)
{
	struct bt_conn *conn = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			conn = &conns[i];
			(void)memset(conn, 0, sizeof(*conn));
			conn->handle = i;
			break;
		}
	}

	if (!conn) {
		return NULL;
	}

	k_delayed_work_init(&conn->update_work, conn_update_timeout);

	k_work_init(&conn->tx_complete_work, tx_complete_work);

	atomic_set(&conn->ref, 1);

	return conn;
}

#if defined(CONFIG_BT_BREDR)
void bt_sco_cleanup(struct bt_conn *sco_conn)
{
	bt_conn_unref(sco_conn->sco.acl);
	sco_conn->sco.acl = NULL;
	bt_conn_unref(sco_conn);
}

static struct bt_conn *sco_conn_new(void)
{
	struct bt_conn *sco_conn = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(sco_conns); i++) {
		if (!atomic_get(&sco_conns[i].ref)) {
			sco_conn = &sco_conns[i];
			break;
		}
	}

	if (!sco_conn) {
		return NULL;
	}

	(void)memset(sco_conn, 0, sizeof(*sco_conn));

	atomic_set(&sco_conn->ref, 1);

	return sco_conn;
}

struct bt_conn *bt_conn_create_br(const bt_addr_t *peer,
				  const struct bt_br_conn_param *param)
{
	struct bt_hci_cp_connect *cp;
	struct bt_conn *conn;
	struct net_buf *buf;

	conn = bt_conn_lookup_addr_br(peer);
	if (conn) {
		switch (conn->state) {
		case BT_CONN_CONNECT:
		case BT_CONN_CONNECTED:
			return conn;
		default:
			bt_conn_unref(conn);
			return NULL;
		}
	}

	conn = bt_conn_add_br(peer);
	if (!conn) {
		return NULL;
	}

	buf = bt_hci_cmd_create(BT_HCI_OP_CONNECT, sizeof(*cp));
	if (!buf) {
		bt_conn_unref(conn);
		return NULL;
	}

	cp = net_buf_add(buf, sizeof(*cp));

	(void)memset(cp, 0, sizeof(*cp));

	memcpy(&cp->bdaddr, peer, sizeof(cp->bdaddr));
	cp->packet_type = sys_cpu_to_le16(0xcc18); /* DM1 DH1 DM3 DH5 DM5 DH5 */
	cp->pscan_rep_mode = 0x02; /* R2 */
	cp->allow_role_switch = param->allow_role_switch ? 0x01 : 0x00;
	cp->clock_offset = 0x0000; /* TODO used cached clock offset */

	if (bt_hci_cmd_send_sync(BT_HCI_OP_CONNECT, buf, NULL) < 0) {
		bt_conn_unref(conn);
		return NULL;
	}

	bt_conn_set_state(conn, BT_CONN_CONNECT);
	conn->role = BT_CONN_ROLE_MASTER;

	return conn;
}

struct bt_conn *bt_conn_create_sco(const bt_addr_t *peer)
{
	struct bt_hci_cp_setup_sync_conn *cp;
	struct bt_conn *sco_conn;
	struct net_buf *buf;
	int link_type;

	sco_conn = bt_conn_lookup_addr_sco(peer);
	if (sco_conn) {
		switch (sco_conn->state) {
		case BT_CONN_CONNECT:
		case BT_CONN_CONNECTED:
			return sco_conn;
		default:
			bt_conn_unref(sco_conn);
			return NULL;
		}
	}

	if (BT_FEAT_LMP_ESCO_CAPABLE(bt_dev.features)) {
		link_type = BT_HCI_ESCO;
	} else {
		link_type = BT_HCI_SCO;
	}

	sco_conn = bt_conn_add_sco(peer, link_type);
	if (!sco_conn) {
		return NULL;
	}

	buf = bt_hci_cmd_create(BT_HCI_OP_SETUP_SYNC_CONN, sizeof(*cp));
	if (!buf) {
		bt_sco_cleanup(sco_conn);
		return NULL;
	}

	cp = net_buf_add(buf, sizeof(*cp));

	(void)memset(cp, 0, sizeof(*cp));

	BT_ERR("handle : %x", sco_conn->sco.acl->handle);

	cp->handle = sco_conn->sco.acl->handle;
	cp->pkt_type = sco_conn->sco.pkt_type;
	cp->tx_bandwidth = 0x00001f40;
	cp->rx_bandwidth = 0x00001f40;
	cp->max_latency = 0x0007;
	cp->retrans_effort = 0x01;
	cp->content_format = BT_VOICE_CVSD_16BIT;

	if (bt_hci_cmd_send_sync(BT_HCI_OP_SETUP_SYNC_CONN, buf,
				 NULL) < 0) {
		bt_sco_cleanup(sco_conn);
		return NULL;
	}

	bt_conn_set_state(sco_conn, BT_CONN_CONNECT);

	return sco_conn;
}

struct bt_conn *bt_conn_lookup_addr_sco(const bt_addr_t *peer)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sco_conns); i++) {
		if (!atomic_get(&sco_conns[i].ref)) {
			continue;
		}

		if (sco_conns[i].type != BT_CONN_TYPE_SCO) {
			continue;
		}

		if (!bt_addr_cmp(peer, &sco_conns[i].sco.acl->br.dst)) {
			return bt_conn_ref(&sco_conns[i]);
		}
	}

	return NULL;
}

struct bt_conn *bt_conn_lookup_addr_br(const bt_addr_t *peer)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			continue;
		}

		if (conns[i].type != BT_CONN_TYPE_BR) {
			continue;
		}

		if (!bt_addr_cmp(peer, &conns[i].br.dst)) {
			return bt_conn_ref(&conns[i]);
		}
	}

	return NULL;
}

struct bt_conn *bt_conn_add_sco(const bt_addr_t *peer, int link_type)
{
	struct bt_conn *sco_conn = sco_conn_new();

	if (!sco_conn) {
		return NULL;
	}

	sco_conn->sco.acl = bt_conn_lookup_addr_br(peer);
	sco_conn->type = BT_CONN_TYPE_SCO;

	if (link_type == BT_HCI_SCO) {
		if (BT_FEAT_LMP_ESCO_CAPABLE(bt_dev.features)) {
			sco_conn->sco.pkt_type = (bt_dev.br.esco_pkt_type &
						  ESCO_PKT_MASK);
		} else {
			sco_conn->sco.pkt_type = (bt_dev.br.esco_pkt_type &
						  SCO_PKT_MASK);
		}
	} else if (link_type == BT_HCI_ESCO) {
		sco_conn->sco.pkt_type = (bt_dev.br.esco_pkt_type &
					  ~EDR_ESCO_PKT_MASK);
	}

	return sco_conn;
}

struct bt_conn *bt_conn_add_br(const bt_addr_t *peer)
{
	struct bt_conn *conn = conn_new();

	if (!conn) {
		return NULL;
	}

	bt_addr_copy(&conn->br.dst, peer);
	conn->type = BT_CONN_TYPE_BR;

	return conn;
}

static int pin_code_neg_reply(const bt_addr_t *bdaddr)
{
	struct bt_hci_cp_pin_code_neg_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_PIN_CODE_NEG_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	bt_addr_copy(&cp->bdaddr, bdaddr);

	return bt_hci_cmd_send_sync(BT_HCI_OP_PIN_CODE_NEG_REPLY, buf, NULL);
}

static int pin_code_reply(struct bt_conn *conn, const char *pin, u8_t len)
{
	struct bt_hci_cp_pin_code_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_PIN_CODE_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));

	bt_addr_copy(&cp->bdaddr, &conn->br.dst);
	cp->pin_len = len;
	strncpy((char *)cp->pin_code, pin, sizeof(cp->pin_code));

	return bt_hci_cmd_send_sync(BT_HCI_OP_PIN_CODE_REPLY, buf, NULL);
}

int bt_conn_auth_pincode_entry(struct bt_conn *conn, const char *pin)
{
	size_t len;

	if (!bt_auth) {
		return -EINVAL;
	}

	if (conn->type != BT_CONN_TYPE_BR) {
		return -EINVAL;
	}

	len = strlen(pin);
	if (len > 16) {
		return -EINVAL;
	}

	if (conn->required_sec_level == BT_SECURITY_L3 && len < 16) {
		BT_WARN("PIN code for %s is not 16 bytes wide",
			bt_addr_str(&conn->br.dst));
		return -EPERM;
	}

	/* Allow user send entered PIN to remote, then reset user state. */
	if (!atomic_test_and_clear_bit(conn->flags, BT_CONN_USER)) {
		return -EPERM;
	}

	if (len == 16) {
		atomic_set_bit(conn->flags, BT_CONN_BR_LEGACY_SECURE);
	}

	return pin_code_reply(conn, pin, len);
}

void bt_conn_pin_code_req(struct bt_conn *conn)
{
	if (bt_auth && bt_auth->pincode_entry) {
		bool secure = false;

		if (conn->required_sec_level == BT_SECURITY_L3) {
			secure = true;
		}

		atomic_set_bit(conn->flags, BT_CONN_USER);
		atomic_set_bit(conn->flags, BT_CONN_BR_PAIRING);
		bt_auth->pincode_entry(conn, secure);
	} else {
		pin_code_neg_reply(&conn->br.dst);
	}
}

u8_t bt_conn_get_io_capa(void)
{
	if (!bt_auth) {
		return BT_IO_NO_INPUT_OUTPUT;
	}

	if (bt_auth->passkey_confirm && bt_auth->passkey_display) {
		return BT_IO_DISPLAY_YESNO;
	}

	if (bt_auth->passkey_entry) {
		return BT_IO_KEYBOARD_ONLY;
	}

	if (bt_auth->passkey_display) {
		return BT_IO_DISPLAY_ONLY;
	}

	return BT_IO_NO_INPUT_OUTPUT;
}

static u8_t ssp_pair_method(const struct bt_conn *conn)
{
	return ssp_method[conn->br.remote_io_capa][bt_conn_get_io_capa()];
}

u8_t bt_conn_ssp_get_auth(const struct bt_conn *conn)
{
	/* Validate no bond auth request, and if valid use it. */
	if ((conn->br.remote_auth == BT_HCI_NO_BONDING) ||
	    ((conn->br.remote_auth == BT_HCI_NO_BONDING_MITM) &&
	     (ssp_pair_method(conn) > JUST_WORKS))) {
		return conn->br.remote_auth;
	}

	/* Local & remote have enough IO capabilities to get MITM protection. */
	if (ssp_pair_method(conn) > JUST_WORKS) {
		return conn->br.remote_auth | BT_MITM;
	}

	/* No MITM protection possible so ignore remote MITM requirement. */
	return (conn->br.remote_auth & ~BT_MITM);
}

static int ssp_confirm_reply(struct bt_conn *conn)
{
	struct bt_hci_cp_user_confirm_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_USER_CONFIRM_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	bt_addr_copy(&cp->bdaddr, &conn->br.dst);

	return bt_hci_cmd_send_sync(BT_HCI_OP_USER_CONFIRM_REPLY, buf, NULL);
}

static int ssp_confirm_neg_reply(struct bt_conn *conn)
{
	struct bt_hci_cp_user_confirm_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_USER_CONFIRM_NEG_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	bt_addr_copy(&cp->bdaddr, &conn->br.dst);

	return bt_hci_cmd_send_sync(BT_HCI_OP_USER_CONFIRM_NEG_REPLY, buf,
				    NULL);
}

void bt_conn_ssp_auth_complete(struct bt_conn *conn, u8_t status)
{
	if (!status) {
		bool bond = !atomic_test_bit(conn->flags, BT_CONN_BR_NOBOND);

		if (bt_auth && bt_auth->pairing_complete) {
			bt_auth->pairing_complete(conn, bond);
		}
	} else {
		if (bt_auth && bt_auth->pairing_failed) {
			bt_auth->pairing_failed(conn, status);
		}
	}
}

void bt_conn_ssp_auth(struct bt_conn *conn, u32_t passkey)
{
	conn->br.pairing_method = ssp_pair_method(conn);

	/*
	 * If local required security is HIGH then MITM is mandatory.
	 * MITM protection is no achievable when SSP 'justworks' is applied.
	 */
	if (conn->required_sec_level > BT_SECURITY_L2 &&
	    conn->br.pairing_method == JUST_WORKS) {
		BT_DBG("MITM protection infeasible for required security");
		ssp_confirm_neg_reply(conn);
		return;
	}

	switch (conn->br.pairing_method) {
	case PASSKEY_CONFIRM:
		atomic_set_bit(conn->flags, BT_CONN_USER);
		bt_auth->passkey_confirm(conn, passkey);
		break;
	case PASSKEY_DISPLAY:
		atomic_set_bit(conn->flags, BT_CONN_USER);
		bt_auth->passkey_display(conn, passkey);
		break;
	case PASSKEY_INPUT:
		atomic_set_bit(conn->flags, BT_CONN_USER);
		bt_auth->passkey_entry(conn);
		break;
	case JUST_WORKS:
		/*
		 * When local host works as pairing acceptor and 'justworks'
		 * model is applied then notify user about such pairing request.
		 * [BT Core 4.2 table 5.7, Vol 3, Part C, 5.2.2.6]
		 */
		if (bt_auth && bt_auth->pairing_confirm &&
		    !atomic_test_bit(conn->flags,
				     BT_CONN_BR_PAIRING_INITIATOR)) {
			atomic_set_bit(conn->flags, BT_CONN_USER);
			bt_auth->pairing_confirm(conn);
			break;
		}
		ssp_confirm_reply(conn);
		break;
	default:
		break;
	}
}

static int ssp_passkey_reply(struct bt_conn *conn, unsigned int passkey)
{
	struct bt_hci_cp_user_passkey_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_USER_PASSKEY_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	bt_addr_copy(&cp->bdaddr, &conn->br.dst);
	cp->passkey = sys_cpu_to_le32(passkey);

	return bt_hci_cmd_send_sync(BT_HCI_OP_USER_PASSKEY_REPLY, buf, NULL);
}

static int ssp_passkey_neg_reply(struct bt_conn *conn)
{
	struct bt_hci_cp_user_passkey_neg_reply *cp;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_USER_PASSKEY_NEG_REPLY, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	bt_addr_copy(&cp->bdaddr, &conn->br.dst);

	return bt_hci_cmd_send_sync(BT_HCI_OP_USER_PASSKEY_NEG_REPLY, buf,
				    NULL);
}

static int bt_hci_connect_br_cancel(struct bt_conn *conn)
{
	struct bt_hci_cp_connect_cancel *cp;
	struct bt_hci_rp_connect_cancel *rp;
	struct net_buf *buf, *rsp;
	int err;

	buf = bt_hci_cmd_create(BT_HCI_OP_CONNECT_CANCEL, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	memcpy(&cp->bdaddr, &conn->br.dst, sizeof(cp->bdaddr));

	err = bt_hci_cmd_send_sync(BT_HCI_OP_CONNECT_CANCEL, buf, &rsp);
	if (err) {
		return err;
	}

	rp = (void *)rsp->data;

	err = rp->status ? -EIO : 0;

	net_buf_unref(rsp);

	return err;
}

static int conn_auth(struct bt_conn *conn)
{
	struct bt_hci_cp_auth_requested *auth;
	struct net_buf *buf;

	BT_DBG("");

	buf = bt_hci_cmd_create(BT_HCI_OP_AUTH_REQUESTED, sizeof(*auth));
	if (!buf) {
		return -ENOBUFS;
	}

	auth = net_buf_add(buf, sizeof(*auth));
	auth->handle = sys_cpu_to_le16(conn->handle);

	atomic_set_bit(conn->flags, BT_CONN_BR_PAIRING_INITIATOR);

	return bt_hci_cmd_send_sync(BT_HCI_OP_AUTH_REQUESTED, buf, NULL);
}
#endif /* CONFIG_BT_BREDR */

#if defined(CONFIG_BT_SMP)
void bt_conn_identity_resolved(struct bt_conn *conn)
{
	const bt_addr_le_t *rpa;
	struct bt_conn_cb *cb;

	if (conn->role == BT_HCI_ROLE_MASTER) {
		rpa = &conn->le.resp_addr;
	} else {
		rpa = &conn->le.init_addr;
	}

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->identity_resolved) {
			cb->identity_resolved(conn, rpa, &conn->le.dst);
		}
	}
}

int bt_conn_le_start_encryption(struct bt_conn *conn, u8_t rand[8],
				u8_t ediv[2], const u8_t *ltk, size_t len)
{
#if !(defined(CONFIG_BT_USE_HCI_API) && CONFIG_BT_USE_HCI_API)
	struct bt_hci_cp_le_start_encryption *cp;
	struct net_buf *buf;

	if (conn->state != BT_CONN_CONNECTED) {
		return -ENOTCONN;
	}

	buf = bt_hci_cmd_create(BT_HCI_OP_LE_START_ENCRYPTION, sizeof(*cp));
	if (!buf) {
		return -ENOBUFS;
	}

	cp = net_buf_add(buf, sizeof(*cp));
	cp->handle = sys_cpu_to_le16(conn->handle);
	memcpy(&cp->rand, rand, sizeof(cp->rand));
	memcpy(&cp->ediv, ediv, sizeof(cp->ediv));

	memcpy(cp->ltk, ltk, len);
	if (len < sizeof(cp->ltk)) {
		(void)memset(cp->ltk + len, 0, sizeof(cp->ltk) - len);
	}
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
	return bt_hci_cmd_send_cb(BT_HCI_OP_LE_START_ENCRYPTION, buf, NULL);
#else
	return bt_hci_cmd_send_sync(BT_HCI_OP_LE_START_ENCRYPTION, buf, NULL);
#endif
#else
	u8_t ltk_buf[16];

	memcpy(ltk_buf, ltk, len);

	if (len < sizeof(ltk_buf)) {
		memset(ltk_buf + len, 0, sizeof(ltk_buf) - len);
	}

	return hci_api_le_start_encrypt(conn->handle, rand, ediv, ltk_buf);
#endif
}
#endif /* CONFIG_BT_SMP */

#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_BREDR)
u8_t bt_conn_enc_key_size(struct bt_conn *conn)
{
	if (!conn->encrypt) {
		return 0;
	}

	if (IS_ENABLED(CONFIG_BT_BREDR) &&
	    conn->type == BT_CONN_TYPE_BR) {
		struct bt_hci_cp_read_encryption_key_size *cp;
		struct bt_hci_rp_read_encryption_key_size *rp;
		struct net_buf *buf;
		struct net_buf *rsp;
		u8_t key_size;

		buf = bt_hci_cmd_create(BT_HCI_OP_READ_ENCRYPTION_KEY_SIZE,
					sizeof(*cp));
		if (!buf) {
			return 0;
		}

		cp = net_buf_add(buf, sizeof(*cp));
		cp->handle = sys_cpu_to_le16(conn->handle);

		if (bt_hci_cmd_send_sync(BT_HCI_OP_READ_ENCRYPTION_KEY_SIZE,
					buf, &rsp)) {
			return 0;
		}

		rp = (void *)rsp->data;

		key_size = rp->status ? 0 : rp->key_size;

		net_buf_unref(rsp);

		return key_size;
	}

	if (IS_ENABLED(CONFIG_BT_SMP)) {
		return conn->le.keys ? conn->le.keys->enc_size : 0;
	}

	return 0;
}

void bt_conn_security_changed(struct bt_conn *conn, enum bt_security_err err)
{
	struct bt_conn_cb *cb;

	for (cb = callback_list; cb; cb = cb->_next) {
		if (cb->security_changed) {
			cb->security_changed(conn, conn->sec_level, err);
		}
	}
#if IS_ENABLED(CONFIG_BT_KEYS_OVERWRITE_OLDEST)
	if (!err && conn->sec_level >= BT_SECURITY_L2) {
		bt_keys_update_usage(conn->id, bt_conn_get_dst(conn));
	}
#endif
}

static int start_security(struct bt_conn *conn)
{
#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR) {
		if (atomic_test_bit(conn->flags, BT_CONN_BR_PAIRING)) {
			return -EBUSY;
		}

		if (conn->required_sec_level > BT_SECURITY_L3) {
			return -ENOTSUP;
		}

		if (bt_conn_get_io_capa() == BT_IO_NO_INPUT_OUTPUT &&
		    conn->required_sec_level > BT_SECURITY_L2) {
			return -EINVAL;
		}

		return conn_auth(conn);
	}
#endif /* CONFIG_BT_BREDR */

	if (IS_ENABLED(CONFIG_BT_SMP)) {
		return bt_smp_start_security(conn);
	}

	return -EINVAL;
}

int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec)
{
	int err;

	if (conn->state != BT_CONN_CONNECTED) {
		return -ENOTCONN;
	}

	if (IS_ENABLED(CONFIG_BT_SMP_SC_ONLY) &&
	    sec < BT_SECURITY_L4) {
		return -EOPNOTSUPP;
	}

	if (IS_ENABLED(CONFIG_BT_SMP_OOB_LEGACY_PAIR_ONLY) &&
	    sec > BT_SECURITY_L3) {
		return -EOPNOTSUPP;
	}

	/* nothing to do */
	if (conn->sec_level >= sec || conn->required_sec_level >= sec) {
		return 0;
	}

	atomic_set_bit_to(conn->flags, BT_CONN_FORCE_PAIR,
			  sec & BT_SECURITY_FORCE_PAIR);
	conn->required_sec_level = sec & ~BT_SECURITY_FORCE_PAIR;

	err = start_security(conn);

	/* reset required security level in case of error */
	if (err) {
		conn->required_sec_level = conn->sec_level;
	}

	return err;
}

bt_security_t bt_conn_get_security(struct bt_conn *conn)
{
	return conn->sec_level;
}
#else
bt_security_t bt_conn_get_security(struct bt_conn *conn)
{
	return BT_SECURITY_L1;
}
#endif /* CONFIG_BT_SMP */

void bt_conn_cb_register(struct bt_conn_cb *cb)
{
    if(callback_list) {
       if(callback_list == cb) {
           return;
	    }

       for(struct bt_conn_cb *temp = callback_list;temp->_next != NULL;temp = temp->_next) {
          if(temp->_next == cb) {
          return;
	       }
	   }
	}
	cb->_next = callback_list;
	callback_list = cb;
}

void bt_conn_cb_unregister(struct bt_conn_cb *cb)
{

	struct bt_conn_cb *temp = callback_list;

	if(!callback_list || !cb) {
       return;
	}

	if(cb == callback_list) {
       callback_list = cb->_next;
	   return;
	}

    for(;temp->_next != NULL;temp = temp->_next) {
       if(temp->_next == cb) {
           temp->_next = cb->_next;
		   cb->_next = NULL;
	   }
	}

}

static void bt_conn_reset_rx_state(struct bt_conn *conn)
{
	if (!conn->rx_len) {
		return;
	}

	net_buf_unref(conn->rx);
	conn->rx = NULL;
	conn->rx_len = 0U;
}

void bt_conn_recv(struct bt_conn *conn, struct net_buf *buf, u8_t flags)
{
	struct bt_l2cap_hdr *hdr;
	u16_t len;

	/* Make sure we notify any pending TX callbacks before processing
	 * new data for this connection.
	 */
	tx_notify(conn);

	BT_DBG("handle %u len %u flags %02x", conn->handle, buf->len, flags);

	/* Check packet boundary flags */
	switch (flags) {
	case BT_ACL_START:
		hdr = (void *)buf->data;
		len = sys_le16_to_cpu(hdr->len);

		BT_DBG("First, len %u final %u", buf->len, len);

		if (conn->rx_len) {
			BT_ERR("Unexpected first L2CAP frame");
			bt_conn_reset_rx_state(conn);
		}

		conn->rx_len = (sizeof(*hdr) + len) - buf->len;
		BT_DBG("rx_len %u", conn->rx_len);
		if (conn->rx_len) {
			conn->rx = buf;
			return;
		}

		break;
	case BT_ACL_CONT:
		if (!conn->rx_len) {
			BT_ERR("Unexpected L2CAP continuation");
			bt_conn_reset_rx_state(conn);
			net_buf_unref(buf);
			return;
		}

		if (buf->len > conn->rx_len) {
			BT_ERR("L2CAP data overflow");
			bt_conn_reset_rx_state(conn);
			net_buf_unref(buf);
			return;
		}

		BT_DBG("Cont, len %u rx_len %u", buf->len, conn->rx_len);

		if (buf->len > net_buf_tailroom(conn->rx)) {
			BT_ERR("Not enough buffer space for L2CAP data");
			bt_conn_reset_rx_state(conn);
			net_buf_unref(buf);
			return;
		}

		net_buf_add_mem(conn->rx, buf->data, buf->len);
		conn->rx_len -= buf->len;
		net_buf_unref(buf);

		if (conn->rx_len) {
			return;
		}

		buf = conn->rx;
		conn->rx = NULL;
		conn->rx_len = 0U;

		break;
	default:
		/* BT_ACL_START_NO_FLUSH and BT_ACL_COMPLETE are not allowed on
		 * LE-U from Controller to Host.
		 * Only BT_ACL_POINT_TO_POINT is supported.
		 */
		BT_ERR("Unexpected ACL flags (0x%02x)", flags);
		bt_conn_reset_rx_state(conn);
		net_buf_unref(buf);
		return;
	}

	hdr = (void *)buf->data;
	len = sys_le16_to_cpu(hdr->len);

	if (sizeof(*hdr) + len != buf->len) {
		BT_ERR("ACL len mismatch (%u != %u)", len, buf->len);
		net_buf_unref(buf);
		return;
	}

	BT_DBG("Successfully parsed %u byte L2CAP packet", buf->len);

	bt_l2cap_recv(conn, buf);
}

static struct bt_conn_tx *conn_tx_alloc(void)
{
	//sys_snode_t *node;
	/* The TX context always get freed in the system workqueue,
	 * so if we're in the same workqueue but there are no immediate
	 * contexts available, there's no chance we'll get one by waiting.
	 */
	//if (k_current_get() == &k_sys_work_q.thread) {
	//	return k_fifo_get(&free_tx, K_NO_WAIT);
	//}
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
	struct bt_conn_tx *tx = k_fifo_get(&free_tx, K_NO_WAIT);

	if (tx) {
		return tx;
	}

	BT_WARN("Unable to get an immediate free conn_tx");
	return NULL;
#else
	if (IS_ENABLED(CONFIG_BT_DEBUG_CONN)) {
		struct bt_conn_tx *tx = k_fifo_get(&free_tx, K_NO_WAIT);

		if (tx) {
			return tx;
		}

		BT_WARN("Unable to get an immediate free conn_tx");
	}

	return k_fifo_get(&free_tx, K_FOREVER);
#endif
}

int bt_conn_send_cb(struct bt_conn *conn, struct net_buf *buf,
		    bt_conn_tx_cb_t cb, void *user_data)
{
	struct bt_conn_tx *tx;

	BT_DBG("conn handle %u buf len %u cb %p user_data %p", conn->handle,
	       buf->len, cb, user_data);

	if (conn->state != BT_CONN_CONNECTED) {
		BT_ERR("not connected!");
		net_buf_unref(buf);
		return -ENOTCONN;
	}

	if (cb) {
		tx = conn_tx_alloc();
		if (!tx) {
			BT_ERR("Unable to allocate TX context");
			net_buf_unref(buf);
			return -ENOBUFS;
		}

		/* Verify that we're still connected after blocking */
		if (conn->state != BT_CONN_CONNECTED) {
			BT_WARN("Disconnected while allocating context");
			net_buf_unref(buf);
			tx_free(tx);
			return -ENOTCONN;
		}

		tx->cb = cb;
		tx->user_data = user_data;
		tx->pending_no_cb = 0U;

		tx_data(buf)->tx = tx;
	} else {
		tx_data(buf)->tx = NULL;
	}

	net_buf_put(&conn->tx_queue, buf);

    return 0;
}

static inline u16_t conn_mtu(struct bt_conn *conn)
{
#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR || !bt_dev.le.mtu) {
		return bt_dev.br.mtu;
	}
#endif /* CONFIG_BT_BREDR */

	return bt_dev.le.mtu;
}

#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
static int send_frag(struct bt_conn *conn, struct net_buf *buf, u8_t flags,
		      bool always_consume)
{
	struct bt_conn_tx *tx = tx_data(buf)->tx;
	struct bt_hci_acl_hdr *hdr;
	u32_t *pending_no_cb;
	unsigned int key;
	int err;
	struct net_buf_simple_state state = {0};

	BT_DBG("conn %p buf %p len %u flags 0x%02x", conn, buf, buf->len,
	       flags);

	/* Wait until the controller can accept ACL packets */
	if (atomic_get(&bt_dev.le.pkts) == 0)
	{
		return -ENOBUFS;
	}

	atomic_dec(&bt_dev.le.pkts);

	net_buf_simple_save(&buf->b, &state);

	/* Check for disconnection while waiting for pkts_sem */
	if (conn->state != BT_CONN_CONNECTED) {
		err = -ENOTCONN;
		goto fail;
	}

	hdr = net_buf_push(buf, sizeof(*hdr));
	hdr->handle = sys_cpu_to_le16(bt_acl_handle_pack(conn->handle, flags));
	hdr->len = sys_cpu_to_le16(buf->len - sizeof(*hdr));

	/* Add to pending, it must be done before bt_buf_set_type */
	key = irq_lock();
	if (tx) {
		sys_slist_append(&conn->tx_pending, &tx->node);
	} else {
		struct bt_conn_tx *tail_tx;

		tail_tx = (void *)sys_slist_peek_tail(&conn->tx_pending);
		if (tail_tx) {
			pending_no_cb = &tail_tx->pending_no_cb;
		} else {
			pending_no_cb = &conn->pending_no_cb;
		}

		(*pending_no_cb)++;
	}
	irq_unlock(key);

	bt_buf_set_type(buf, BT_BUF_ACL_OUT);

	err = bt_send(buf);
	if (err) {

		key = irq_lock();
		/* Roll back the pending TX info */
		if (tx) {
			sys_slist_find_and_remove(&conn->tx_pending, &tx->node);
		} else {
			__ASSERT_NO_MSG(*pending_no_cb > 0);
			(*pending_no_cb)--;
		}
		irq_unlock(key);
		goto fail;
	}

	return 0;

fail:
	atomic_inc(&bt_dev.le.pkts);


	if (err == -ENOMEM)
	{
		err = -ENOBUFS;
	}
	else 
	{
		BT_ERR("Unable to send to driver (err %d)", err);
		err = -EIO;
	}

	if (err != -ENOBUFS && always_consume) {
		if (tx) {
			tx_free(tx);
		}
		net_buf_unref(buf);
	}
	else
	{
		/* restore buf, it will reuse later */
		net_buf_simple_restore(&buf->b, &state);
		tx_data(buf)->tx = tx;
	}

	return err;
}

static struct net_buf *create_frag(struct bt_conn *conn, struct net_buf *buf)
{
	struct net_buf *frag;
	u16_t frag_len;

	frag = bt_conn_create_frag(0);

	if (!frag)
	{
		return NULL;
	}

	if (conn->state != BT_CONN_CONNECTED) {
		net_buf_unref(frag);
		return NULL;
	}

	/* Fragments never have a TX completion callback */
	tx_data(frag)->tx = NULL;

	frag_len = MIN(conn_mtu(conn), net_buf_tailroom(frag));

	net_buf_add_mem(frag, buf->data, frag_len);
	net_buf_pull(buf, frag_len);

	return frag;
}

static bool send_buf(struct bt_conn *conn, struct net_buf *buf)
{
	struct net_buf *frag;
	int err;
	BT_DBG("conn %p buf %p len %u", conn, buf, buf->len);

	/* buf reserve size > conn_mtu means this buf is a resending buffer, and is must be a BT_ACL_CONT buffer*/
	if (net_buf_headroom(buf) >= conn_mtu(conn))
	{
		/* Send directly if the packet fits the ACL MTU */
		if (buf->len <= conn_mtu(conn)) {
			err = send_frag(conn, buf, BT_ACL_CONT, false);
			if (err == -ENOBUFS)
			{
				k_queue_prepend(&conn->tx_queue._queue, buf);
				return true;
			} if (err)
			{
				return false;
			}

			return true;
		}
	}
	else
	{
		/* Send directly if the packet fits the ACL MTU */
		if (buf->len <= conn_mtu(conn)) {
			err = send_frag(conn, buf, BT_ACL_START_NO_FLUSH, false);
			if (err == -ENOBUFS)
			{
				k_queue_prepend(&conn->tx_queue._queue, buf);
				return true;
			}
			else if (err)
			{
				return false;
			}
			return true;
		}

		/* Create & enqueue first fragment */
		frag = create_frag(conn, buf);
		if (!frag) {
			k_queue_prepend(&conn->tx_queue._queue, buf);
			return true;
		}

		err = send_frag(conn, frag, BT_ACL_START_NO_FLUSH, true);
		if (err == -ENOBUFS)
		{
			memcpy(net_buf_push(buf, frag->len), frag->data, frag->len);
			k_queue_prepend(&conn->tx_queue._queue, buf);
			net_buf_unref(frag);
			return true;
		}
		else if (err)
		{
			return false;
		}
	}

	/*
	 * Send the fragments. For the last one simply use the original
	 * buffer (which works since we've used net_buf_pull on it.
	 */
	while (buf->len > conn_mtu(conn)) {
		frag = create_frag(conn, buf);
		if (!frag) {
			k_queue_prepend(&conn->tx_queue._queue, buf);
			return true;
		}

		err = send_frag(conn, frag, BT_ACL_CONT, true);
		if (err == -ENOBUFS)
		{
			memcpy(net_buf_push(buf, frag->len), frag->data, frag->len);
			k_queue_prepend(&conn->tx_queue._queue, buf);
			net_buf_unref(frag);
			return true;
		}
		else if (err)
		{
			return false;
		}
	}

	err = send_frag(conn, buf, BT_ACL_CONT, false);
	if (err == -ENOBUFS)
	{
		k_queue_prepend(&conn->tx_queue._queue, buf);
		return true;
	}
	else if (err)
	{
		return false;
	}

	return true;
}
#else
static bool send_frag(struct bt_conn *conn, struct net_buf *buf, u8_t flags,
		      bool always_consume)
{
	struct bt_conn_tx *tx = tx_data(buf)->tx;
	struct bt_hci_acl_hdr *hdr;
	u32_t *pending_no_cb;
	unsigned int key;
	int err;

	BT_DBG("conn %p buf %p len %u flags 0x%02x", conn, buf, buf->len,
	       flags);

	/* Wait until the controller can accept ACL packets */
	k_sem_take(bt_conn_get_pkts(conn), K_FOREVER);

	/* Check for disconnection while waiting for pkts_sem */
	if (conn->state != BT_CONN_CONNECTED) {
		goto fail;
	}

	hdr = net_buf_push(buf, sizeof(*hdr));
	hdr->handle = sys_cpu_to_le16(bt_acl_handle_pack(conn->handle, flags));
	hdr->len = sys_cpu_to_le16(buf->len - sizeof(*hdr));

	/* Add to pending, it must be done before bt_buf_set_type */
	key = irq_lock();
	if (tx) {
		sys_slist_append(&conn->tx_pending, &tx->node);
	} else {
		struct bt_conn_tx *tail_tx;

		tail_tx = (void *)sys_slist_peek_tail(&conn->tx_pending);
		if (tail_tx) {
			pending_no_cb = &tail_tx->pending_no_cb;
		} else {
			pending_no_cb = &conn->pending_no_cb;
		}

		(*pending_no_cb)++;
	}
	irq_unlock(key);

	bt_buf_set_type(buf, BT_BUF_ACL_OUT);

	err = bt_send(buf);
	if (err) {
		BT_ERR("Unable to send to driver (err %d)", err);
		key = irq_lock();
		/* Roll back the pending TX info */
		if (tx) {
			sys_slist_find_and_remove(&conn->tx_pending, &tx->node);
		} else {
			__ASSERT_NO_MSG(*pending_no_cb > 0);
			(*pending_no_cb)--;
		}
		irq_unlock(key);
		goto fail;
	}

	return true;

fail:
	k_sem_give(bt_conn_get_pkts(conn));
	if (tx) {
		tx_free(tx);
	}

	if (always_consume) {
		net_buf_unref(buf);
	}
	return false;
}

static struct net_buf *create_frag(struct bt_conn *conn, struct net_buf *buf)
{
	struct net_buf *frag;
	u16_t frag_len;

	frag = bt_conn_create_frag(0);

	if (conn->state != BT_CONN_CONNECTED) {
		net_buf_unref(frag);
		return NULL;
	}

	/* Fragments never have a TX completion callback */
	tx_data(frag)->tx = NULL;

	frag_len = MIN(conn_mtu(conn), net_buf_tailroom(frag));

	net_buf_add_mem(frag, buf->data, frag_len);
	net_buf_pull(buf, frag_len);

	return frag;
}

static bool send_buf(struct bt_conn *conn, struct net_buf *buf)
{
	struct net_buf *frag;

	BT_DBG("conn %p buf %p len %u", conn, buf, buf->len);

	/* Send directly if the packet fits the ACL MTU */
	if (buf->len <= conn_mtu(conn)) {
		return send_frag(conn, buf, BT_ACL_START_NO_FLUSH, false);
	}

	/* Create & enqueue first fragment */
	frag = create_frag(conn, buf);
	if (!frag) {
		return false;
	}

	if (!send_frag(conn, frag, BT_ACL_START_NO_FLUSH, true)) {
		return false;
	}

	/*
	 * Send the fragments. For the last one simply use the original
	 * buffer (which works since we've used net_buf_pull on it.
	 */
	while (buf->len > conn_mtu(conn)) {
		frag = create_frag(conn, buf);
		if (!frag) {
			return false;
		}

		if (!send_frag(conn, frag, BT_ACL_CONT, true)) {
			return false;
		}
	}

	return send_frag(conn, buf, BT_ACL_CONT, false);
}

#endif
static struct k_poll_signal conn_change =
		K_POLL_SIGNAL_INITIALIZER(conn_change);

static void conn_cleanup(struct bt_conn *conn)
{
	struct net_buf *buf;

	/* Give back any allocated buffers */
	while ((buf = net_buf_get(&conn->tx_queue, K_NO_WAIT))) {
		if (tx_data(buf)->tx) {
			tx_free(tx_data(buf)->tx);
		}

		net_buf_unref(buf);
	}

	__ASSERT(sys_slist_is_empty(&conn->tx_pending), "Pending TX packets");
	__ASSERT_NO_MSG(conn->pending_no_cb == 0);

	bt_conn_reset_rx_state(conn);

	k_delayed_work_submit(&conn->update_work, K_NO_WAIT);
}

int bt_conn_prepare_events(struct k_poll_event events[])
{
	int i, ev_count = 0;

	//BT_DBG("");

	conn_change.signaled = 0U;
	k_poll_event_init(&events[ev_count++], K_POLL_TYPE_SIGNAL,
			  K_POLL_MODE_NOTIFY_ONLY, &conn_change);

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		struct bt_conn *conn = &conns[i];

		if (!atomic_get(&conn->ref)) {
			continue;
		}

		if (conn->state == BT_CONN_DISCONNECTED &&
		    atomic_test_and_clear_bit(conn->flags, BT_CONN_CLEANUP)) {
			conn_cleanup(conn);
			continue;
		}

		if (conn->state != BT_CONN_CONNECTED) {
			continue;
		}

		//BT_DBG("Adding conn %p to poll list", conn);

		k_poll_event_init(&events[ev_count],
				  K_POLL_TYPE_FIFO_DATA_AVAILABLE,
				  K_POLL_MODE_NOTIFY_ONLY,
				  &conn->tx_queue);
		events[ev_count++].tag = BT_EVENT_CONN_TX_QUEUE;
	}

	return ev_count;
}

void bt_conn_process_tx(struct bt_conn *conn)
{
	struct net_buf *buf;

	BT_DBG("conn %p", conn);

	if (conn->state == BT_CONN_DISCONNECTED &&
	    atomic_test_and_clear_bit(conn->flags, BT_CONN_CLEANUP)) {
		BT_DBG("handle %u disconnected - cleaning up", conn->handle);
		conn_cleanup(conn);
		return;
	}

	/* Get next ACL packet for connection */
	buf = net_buf_get(&conn->tx_queue, K_NO_WAIT);
	if(!buf) {
		return;
	}
	BT_ASSERT(buf);
	if (!send_buf(conn, buf)) {
		struct bt_conn_tx *tx = tx_data(buf)->tx;
		if (tx) {
			tx_free(tx);
		}
		net_buf_unref(buf);
	}
}

bool bt_conn_exists_le(u8_t id, const bt_addr_le_t *peer)
{
	struct bt_conn *conn = bt_conn_lookup_addr_le(id, peer);

	if (conn) {
		/* Connection object already exists.
		 * If the connection state is not "disconnected",then the
		 * connection was created but has not yet been disconnected.
		 * If the connection state is "disconnected" then the connection
		 * still has valid references. The last reference of the stack
		 * is released after the disconnected callback.
		 */
		BT_WARN("Found valid connection in %s state",
			state2str(conn->state));
		bt_conn_unref(conn);
		return true;
	}

	return false;
}

struct bt_conn *bt_conn_add_le(u8_t id, const bt_addr_le_t *peer)
{
	struct bt_conn *conn = conn_new();

	if (!conn) {
		return NULL;
	}

	conn->id = id;
	bt_addr_le_copy(&conn->le.dst, peer);
#if defined(CONFIG_BT_SMP)
	conn->sec_level = BT_SECURITY_L1;
	conn->required_sec_level = BT_SECURITY_L1;
#endif /* CONFIG_BT_SMP */
	conn->type = BT_CONN_TYPE_LE;
	conn->le.interval_min = BT_GAP_INIT_CONN_INT_MIN;
	conn->le.interval_max = BT_GAP_INIT_CONN_INT_MAX;

	return conn;
}

static void process_unack_tx(struct bt_conn *conn)
{
	/* Return any unacknowledged packets */
	while (1) {
		struct bt_conn_tx *tx;
		sys_snode_t *node;
		unsigned int key;

		key = irq_lock();

		if (conn->pending_no_cb) {
			conn->pending_no_cb--;
			irq_unlock(key);
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
			atomic_inc(&bt_dev.le.pkts);
#else
			k_sem_give(bt_conn_get_pkts(conn));
#endif
			continue;
		}

		node = sys_slist_get(&conn->tx_pending);
		irq_unlock(key);

		if (!node) {
			break;
		}

		tx = CONTAINER_OF(node, struct bt_conn_tx, node);

		key = irq_lock();
		conn->pending_no_cb = tx->pending_no_cb;
		tx->pending_no_cb = 0U;
		irq_unlock(key);

		tx_free(tx);

#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
		atomic_inc(&bt_dev.le.pkts);
#else
		k_sem_give(bt_conn_get_pkts(conn));
#endif
	}
}

void bt_conn_set_state(struct bt_conn *conn, bt_conn_state_t state)
{
	bt_conn_state_t old_state;

	BT_DBG("%s -> %s", state2str(conn->state), state2str(state));

	if (conn->state == state) {
		BT_WARN("no transition %s", state2str(state));
		return;
	}

	old_state = conn->state;
	conn->state = state;

	/* Actions needed for exiting the old state */
	switch (old_state) {
	case BT_CONN_DISCONNECTED:
		/* Take a reference for the first state transition after
		 * bt_conn_add_le() and keep it until reaching DISCONNECTED
		 * again.
		 */
		bt_conn_ref(conn);
		break;
	case BT_CONN_CONNECT:
		if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
		    conn->type == BT_CONN_TYPE_LE) {
			BT_DBG("k_delayed_work_cancel(&conn->update_work)");
			k_delayed_work_cancel(&conn->update_work);
		}
		break;
	default:
		break;
	}

	/* Actions needed for entering the new state */
	switch (conn->state) {
	case BT_CONN_CONNECTED:
		if (conn->type == BT_CONN_TYPE_SCO) {
			/* TODO: Notify sco connected */
			break;
		}

		bt_dev.le.mtu = bt_dev.le.mtu_init;
		k_fifo_init(&conn->tx_queue);
		k_poll_signal_raise(&conn_change, 0);

		sys_slist_init(&conn->channels);

		bt_l2cap_connected(conn);
		notify_connected(conn);
		break;
	case BT_CONN_DISCONNECTED:
		if (conn->type == BT_CONN_TYPE_SCO) {
			/* TODO: Notify sco disconnected */
			bt_conn_unref(conn);
			break;
		}

		/* Notify disconnection and queue a dummy buffer to wake
		 * up and stop the tx thread for states where it was
		 * running.
		 */
		switch (old_state) {
		case BT_CONN_CONNECTED:
		case BT_CONN_DISCONNECT:
			process_unack_tx(conn);
			tx_notify(conn);

			/* Cancel Connection Update if it is pending */
			if (conn->type == BT_CONN_TYPE_LE) {
				BT_DBG("k_delayed_work_cancel(&conn->update_work)");
				k_delayed_work_cancel(&conn->update_work);
			}

			atomic_set_bit(conn->flags, BT_CONN_CLEANUP);
			k_poll_signal_raise(&conn_change, 0);

			/* The last ref will be dropped during cleanup */
			break;
		case BT_CONN_CONNECT:
			/* LE Create Connection command failed. This might be
			 * directly from the API, don't notify application in
			 * this case.
			 */
			if (conn->err) {
				notify_connected(conn);
			}

			bt_conn_unref(conn);
			break;
		case BT_CONN_CONNECT_SCAN:
			/* this indicate LE Create Connection with peer address
			 * has been stopped. This could either be triggered by
			 * the application through bt_conn_disconnect or by
			 * timeout set by bt_conn_le_create_param.timeout.
			 */
			if (conn->err) {
				notify_connected(conn);
			}

			bt_conn_unref(conn);
			break;
		case BT_CONN_CONNECT_DIR_ADV:
			/* this indicate Directed advertising stopped */
			if (conn->err) {
				notify_connected(conn);
			}

			bt_conn_unref(conn);
			break;
		case BT_CONN_CONNECT_AUTO:
			/* this indicates LE Create Connection with filter
			 * policy has been stopped. This can only be triggered
			 * by the application, so don't notify.
			 */
			bt_conn_unref(conn);
			break;
		case BT_CONN_CONNECT_ADV:
			/* This can only happen when application stops the
			 * advertiser, conn->err is never set in this case.
			 */
			bt_conn_unref(conn);
			break;
		case BT_CONN_DISCONNECTED:
			/* Cannot happen, no transition. */
			break;
		}
		break;
	case BT_CONN_CONNECT_AUTO:
		break;
	case BT_CONN_CONNECT_ADV:
		break;
	case BT_CONN_CONNECT_SCAN:
		break;
	case BT_CONN_CONNECT_DIR_ADV:
		break;
	case BT_CONN_CONNECT:
		if (conn->type == BT_CONN_TYPE_SCO) {
			break;
		}
		/*
		 * Timer is needed only for LE. For other link types controller
		 * will handle connection timeout.
		 */
		if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
		    conn->type == BT_CONN_TYPE_LE) {
			k_delayed_work_submit(&conn->update_work,
				K_MSEC(10 * bt_dev.create_param.timeout));
		}

		break;
	case BT_CONN_DISCONNECT:
		break;
	default:
		BT_WARN("no valid (%u) state was set", state);

		break;
	}
}

struct bt_conn *bt_conn_lookup_handle(u16_t handle)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			continue;
		}

		/* We only care about connections with a valid handle */
		if (conns[i].state != BT_CONN_CONNECTED &&
		    conns[i].state != BT_CONN_DISCONNECT) {
			continue;
		}

		if (conns[i].handle == handle) {
			return bt_conn_ref(&conns[i]);
		}
	}

#if defined(CONFIG_BT_BREDR)
	for (i = 0; i < ARRAY_SIZE(sco_conns); i++) {
		if (!atomic_get(&sco_conns[i].ref)) {
			continue;
		}

		/* We only care about connections with a valid handle */
		if (sco_conns[i].state != BT_CONN_CONNECTED &&
		    sco_conns[i].state != BT_CONN_DISCONNECT) {
			continue;
		}

		if (sco_conns[i].handle == handle) {
			return bt_conn_ref(&sco_conns[i]);
		}
	}
#endif

	return NULL;
}

bool bt_conn_is_peer_addr_le(const struct bt_conn *conn, u8_t id,
			     const bt_addr_le_t *peer)
{
	if (id != conn->id) {
		return false;
	}

	/* Check against conn dst address as it may be the identity address */
	if (!bt_addr_le_cmp(peer, &conn->le.dst)) {
		return true;
	}

	/* Check against initial connection address */
	if (conn->role == BT_HCI_ROLE_MASTER) {
		return bt_addr_le_cmp(peer, &conn->le.resp_addr) == 0;
	}

	return bt_addr_le_cmp(peer, &conn->le.init_addr) == 0;
}

struct bt_conn *bt_conn_lookup_addr_le(u8_t id, const bt_addr_le_t *peer)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			continue;
		}

		if (conns[i].type != BT_CONN_TYPE_LE) {
			continue;
		}

		if (bt_conn_is_peer_addr_le(&conns[i], id, peer)) {
			return bt_conn_ref(&conns[i]);
		}
	}

	return NULL;
}

struct bt_conn *bt_conn_lookup_state_le(u8_t id, const bt_addr_le_t *peer,
					const bt_conn_state_t state)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			continue;
		}

		if (conns[i].type != BT_CONN_TYPE_LE) {
			continue;
		}

		if (peer && !bt_conn_is_peer_addr_le(&conns[i], id, peer)) {
			continue;
		}

		if (conns[i].state == state && conns[i].id == id) {
			return bt_conn_ref(&conns[i]);
		}
	}

	return NULL;
}

void bt_conn_foreach(int type, void (*func)(struct bt_conn *conn, void *data),
		     void *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(conns); i++) {
		if (!atomic_get(&conns[i].ref)) {
			continue;
		}

		if (!(conns[i].type & type)) {
			continue;
		}

		func(&conns[i], data);
	}
#if defined(CONFIG_BT_BREDR)
	if (type & BT_CONN_TYPE_SCO) {
		for (i = 0; i < ARRAY_SIZE(sco_conns); i++) {
			if (!atomic_get(&sco_conns[i].ref)) {
				continue;
			}

			func(&sco_conns[i], data);
		}
	}
#endif /* defined(CONFIG_BT_BREDR) */
}

struct bt_conn *bt_conn_ref(struct bt_conn *conn)
{
	atomic_val_t old = atomic_inc(&conn->ref);

	BT_DBG("handle %u ref %u -> %u", conn->handle, old,
	       atomic_get(&conn->ref));
	(void)old;

	return conn;
}

void bt_conn_unref(struct bt_conn *conn)
{
    if(!conn->ref) {
       return;
	}
	atomic_val_t old = atomic_dec(&conn->ref);
	(void)old;

	BT_DBG("handle %u ref %u -> %u", conn->handle, old,
	       atomic_get(&conn->ref));
}

const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn)
{
	return &conn->le.dst;
}

int bt_conn_get_info(const struct bt_conn *conn, struct bt_conn_info *info)
{
	info->type = conn->type;
	info->role = conn->role;
	info->id = conn->id;

	switch (conn->type) {
	case BT_CONN_TYPE_LE:
		info->le.dst = &conn->le.dst;
		info->le.src = &bt_dev.id_addr[conn->id];
		if (conn->role == BT_HCI_ROLE_MASTER) {
			info->le.local = &conn->le.init_addr;
			info->le.remote = &conn->le.resp_addr;
		} else {
			info->le.local = &conn->le.resp_addr;
			info->le.remote = &conn->le.init_addr;
		}
		info->le.interval = conn->le.interval;
		info->le.latency = conn->le.latency;
		info->le.timeout = conn->le.timeout;
#if defined(CONFIG_BT_USER_PHY_UPDATE)
		info->le.phy = &conn->le.phy;
#endif
#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
		info->le.data_len = &conn->le.data_len;
#endif
		return 0;
#if defined(CONFIG_BT_BREDR)
	case BT_CONN_TYPE_BR:
		info->br.dst = &conn->br.dst;
		return 0;
#endif
	}

	return -EINVAL;
}

int bt_conn_get_remote_info(struct bt_conn *conn,
			    struct bt_conn_remote_info *remote_info)
{
	if (!atomic_test_bit(conn->flags, BT_CONN_AUTO_FEATURE_EXCH) ||
	    (IS_ENABLED(CONFIG_BT_REMOTE_VERSION) &&
	     !atomic_test_bit(conn->flags, BT_CONN_AUTO_VERSION_INFO))) {
		return -EBUSY;
	}

	remote_info->type = conn->type;
#if defined(CONFIG_BT_REMOTE_VERSION)
	/* The conn->rv values will be just zeroes if the operation failed */
	remote_info->version = conn->rv.version;
	remote_info->manufacturer = conn->rv.manufacturer;
	remote_info->subversion = conn->rv.subversion;
#else
	remote_info->version = 0;
	remote_info->manufacturer = 0;
	remote_info->subversion = 0;
#endif

	switch (conn->type) {
	case BT_CONN_TYPE_LE:
		remote_info->le.features = conn->le.features;
		return 0;
#if defined(CONFIG_BT_BREDR)
	case BT_CONN_TYPE_BR:
		/* TODO: Make sure the HCI commands to read br features and
		*  extended features has finished. */
		return -ENOTSUP;
#endif
	default:
		return -EINVAL;
	}
}

static int conn_disconnect(struct bt_conn *conn, u8_t reason)
{
	int err;

	err = bt_hci_disconnect(conn->handle, reason);
	if (err) {
		return err;
	}

	bt_conn_set_state(conn, BT_CONN_DISCONNECT);

	return 0;
}

int bt_conn_le_param_update(struct bt_conn *conn,
			    const struct bt_le_conn_param *param)
{
	BT_DBG("conn %p features 0x%02x params (%d-%d %d %d)", conn,
	       conn->le.features[0], param->interval_min,
	       param->interval_max, param->latency, param->timeout);

	/* Check if there's a need to update conn params */
	if (conn->le.interval >= param->interval_min &&
	    conn->le.interval <= param->interval_max &&
	    conn->le.latency == param->latency &&
	    conn->le.timeout == param->timeout) {
		atomic_clear_bit(conn->flags, BT_CONN_SLAVE_PARAM_SET);
		return -EALREADY;
	}

	if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
	    conn->role == BT_CONN_ROLE_MASTER) {
		return send_conn_le_param_update(conn, param);
	}

	if (IS_ENABLED(CONFIG_BT_PERIPHERAL)) {
		/* if slave conn param update timer expired just send request */
		if (atomic_test_bit(conn->flags, BT_CONN_SLAVE_PARAM_UPDATE)) {
			return send_conn_le_param_update(conn, param);
		}

		/* store new conn params to be used by update timer */
		conn->le.interval_min = param->interval_min;
		conn->le.interval_max = param->interval_max;
		conn->le.pending_latency = param->latency;
		conn->le.pending_timeout = param->timeout;
		atomic_set_bit(conn->flags, BT_CONN_SLAVE_PARAM_SET);
	}

	return 0;
}

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
int bt_conn_le_data_len_update(struct bt_conn *conn,
			       const struct bt_conn_le_data_len_param *param)
{
	if (conn->le.data_len.tx_max_len == param->tx_max_len &&
	    conn->le.data_len.tx_max_time == param->tx_max_time) {
		return -EALREADY;
	}

	if (IS_ENABLED(CONFIG_BT_AUTO_DATA_LEN_UPDATE) &&
	    !atomic_test_bit(conn->flags, BT_CONN_AUTO_DATA_LEN_COMPLETE)) {
		return -EAGAIN;
	}

	return bt_le_set_data_len(conn, param->tx_max_len, param->tx_max_time);
}
#endif

#if defined(CONFIG_BT_USER_PHY_UPDATE)
int bt_conn_le_phy_update(struct bt_conn *conn,
			  const struct bt_conn_le_phy_param *param)
{
	if (conn->le.phy.tx_phy == param->pref_tx_phy &&
	    conn->le.phy.rx_phy == param->pref_rx_phy) {
		return -EALREADY;
	}

	if (IS_ENABLED(CONFIG_BT_AUTO_PHY_UPDATE) &&
	    !atomic_test_bit(conn->flags, BT_CONN_AUTO_PHY_COMPLETE)) {
		return -EAGAIN;
	}

	return bt_le_set_phy(conn, param->pref_tx_phy, param->pref_rx_phy);
}
#endif

int bt_conn_disconnect(struct bt_conn *conn, u8_t reason)
{
	/* Disconnection is initiated by us, so auto connection shall
	 * be disabled. Otherwise the passive scan would be enabled
	 * and we could send LE Create Connection as soon as the remote
	 * starts advertising.
	 */
#if !defined(CONFIG_BT_WHITELIST)
	if (IS_ENABLED(CONFIG_BT_CENTRAL) &&
	    conn->type == BT_CONN_TYPE_LE) {
		bt_le_set_auto_conn(&conn->le.dst, NULL);
	}
#endif /* !defined(CONFIG_BT_WHITELIST) */

	switch (conn->state) {
	case BT_CONN_CONNECT_SCAN:
		conn->err = reason;
		bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
		if (IS_ENABLED(CONFIG_BT_CENTRAL)) {
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
			bt_fsm_le_scan_update(false, bt_dev.fsm);
#else
			bt_le_scan_update(false);
#endif
		}
		return 0;
	case BT_CONN_CONNECT_DIR_ADV:
		BT_WARN("Deprecated: Use bt_le_adv_stop instead");
		conn->err = reason;
		bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
		if (IS_ENABLED(CONFIG_BT_PERIPHERAL)) {
			/* User should unref connection object when receiving
			 * error in connection callback.
			 */
			return bt_le_adv_stop();
		}
		return 0;
	case BT_CONN_CONNECT:
#if defined(CONFIG_BT_BREDR)
		if (conn->type == BT_CONN_TYPE_BR) {
			return bt_hci_connect_br_cancel(conn);
		}
#endif /* CONFIG_BT_BREDR */

		if (IS_ENABLED(CONFIG_BT_CENTRAL)) {
			k_delayed_work_cancel(&conn->update_work);
			return bt_le_create_conn_cancel();
		}

		return 0;
	case BT_CONN_CONNECTED:
		return conn_disconnect(conn, reason);
	case BT_CONN_DISCONNECT:
		return 0;
	case BT_CONN_DISCONNECTED:
	default:
		return -ENOTCONN;
	}
}

#if defined(CONFIG_BT_CENTRAL)
static void bt_conn_set_param_le(struct bt_conn *conn,
				 const struct bt_le_conn_param *param)
{
	conn->le.interval_min = param->interval_min;
	conn->le.interval_max = param->interval_max;
	conn->le.latency = param->latency;
	conn->le.timeout = param->timeout;
}

static bool create_param_validate(const struct bt_conn_le_create_param *param)
{
#if defined(CONFIG_BT_PRIVACY)
	/* Initiation timeout cannot be greater than the RPA timeout */
	const u32_t timeout_max = (MSEC_PER_SEC / 10) * CONFIG_BT_RPA_TIMEOUT;

	if (param->timeout > timeout_max) {
		return false;
	}
#endif

	return true;
}

static void create_param_setup(const struct bt_conn_le_create_param *param)
{
	bt_dev.create_param = *param;

	bt_dev.create_param.timeout =
		(bt_dev.create_param.timeout != 0) ?
		bt_dev.create_param.timeout :
		(MSEC_PER_SEC / 10) * CONFIG_BT_CREATE_CONN_TIMEOUT;

	bt_dev.create_param.interval_coded =
		(bt_dev.create_param.interval_coded != 0) ?
		bt_dev.create_param.interval_coded :
		bt_dev.create_param.interval;

	bt_dev.create_param.window_coded =
		(bt_dev.create_param.window_coded != 0) ?
		bt_dev.create_param.window_coded :
		bt_dev.create_param.window;
}

#if defined(CONFIG_BT_WHITELIST)
int bt_conn_le_create_auto(const struct bt_conn_le_create_param *create_param,
			   const struct bt_le_conn_param *param)
{
	struct bt_conn *conn;
	int err;

	if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY)) {
		return -EAGAIN;
	}

	if (!bt_le_conn_params_valid(param)) {
		return -EINVAL;
	}

	conn = bt_conn_lookup_state_le(BT_ID_DEFAULT, BT_ADDR_LE_NONE,
				       BT_CONN_CONNECT_AUTO);
	if (conn) {
		bt_conn_unref(conn);
		return -EALREADY;
	}

	/* Scanning either to connect or explicit scan, either case scanner was
	 * started by application and should not be stopped.
	 */
	if (atomic_test_bit(bt_dev.flags, BT_DEV_SCANNING)) {
		return -EINVAL;
	}

	if (atomic_test_bit(bt_dev.flags, BT_DEV_INITIATING)) {
		return -EINVAL;
	}

	if (!bt_le_scan_random_addr_check()) {
		return -EINVAL;
	}

	conn = bt_conn_add_le(BT_ID_DEFAULT, BT_ADDR_LE_NONE);
	if (!conn) {
		return -ENOMEM;
	}

	bt_conn_set_param_le(conn, param);
	create_param_setup(create_param);

	atomic_set_bit(conn->flags, BT_CONN_AUTO_CONNECT);
	bt_conn_set_state(conn, BT_CONN_CONNECT_AUTO);

	err = bt_le_create_conn(conn);
	if (err) {
		BT_ERR("Failed to start whitelist scan");
		conn->err = 0;
		bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
		bt_conn_unref(conn);
		return err;
	}

	/* Since we don't give the application a reference to manage in
	 * this case, we need to release this reference here.
	 */
	bt_conn_unref(conn);
	return 0;
}

int bt_conn_create_auto_stop(void)
{
	struct bt_conn *conn;
	int err;

	if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY)) {
		return -EINVAL;
	}

	conn = bt_conn_lookup_state_le(BT_ID_DEFAULT, BT_ADDR_LE_NONE,
				       BT_CONN_CONNECT_AUTO);
	if (!conn) {
		return -EINVAL;
	}

	if (!atomic_test_bit(bt_dev.flags, BT_DEV_INITIATING)) {
		return -EINVAL;
	}

	bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
	bt_conn_unref(conn);

	err = bt_le_create_conn_cancel();
	if (err) {
		BT_ERR("Failed to stop initiator");
		return err;
	}

	return 0;
}
#endif /* defined(CONFIG_BT_WHITELIST) */

int bt_conn_le_create(const bt_addr_le_t *peer,
		      const struct bt_conn_le_create_param *create_param,
		      const struct bt_le_conn_param *conn_param,
		      struct bt_conn **ret_conn)
{
	struct bt_conn *conn;
	bt_addr_le_t dst;
	int err;

	if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY)) {
		return -EAGAIN;
	}

	if (!bt_le_conn_params_valid(conn_param)) {
		return -EINVAL;
	}

	if (!create_param_validate(create_param)) {
		return -EINVAL;
	}

	if (atomic_test_bit(bt_dev.flags, BT_DEV_EXPLICIT_SCAN)) {
		return -EINVAL;
	}

	if (atomic_test_bit(bt_dev.flags, BT_DEV_INITIATING)) {
		return -EALREADY;
	}

	if (!bt_le_scan_random_addr_check()) {
		return -EINVAL;
	}

	if (bt_conn_exists_le(BT_ID_DEFAULT, peer)) {
		return -EINVAL;
	}

	if (peer->type == BT_ADDR_LE_PUBLIC_ID ||
	    peer->type == BT_ADDR_LE_RANDOM_ID) {
		bt_addr_le_copy(&dst, peer);
		dst.type -= BT_ADDR_LE_PUBLIC_ID;
	} else {
		bt_addr_le_copy(&dst, bt_lookup_id_addr(BT_ID_DEFAULT, peer));
	}

	/* Only default identity supported for now */
	conn = bt_conn_add_le(BT_ID_DEFAULT, &dst);
	if (!conn) {
		return -ENOMEM;
	}

	bt_conn_set_param_le(conn, conn_param);
	create_param_setup(create_param);

#if defined(CONFIG_BT_SMP)
	if (!bt_dev.le.rl_size || bt_dev.le.rl_entries > bt_dev.le.rl_size) {
		bt_conn_set_state(conn, BT_CONN_CONNECT_SCAN);
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
		err = bt_fsm_le_scan_update(true, bt_dev.fsm);
#else
		err = bt_le_scan_update(true);
#endif
		if (err) {
			bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
			bt_conn_unref(conn);
			return err;
		}

		*ret_conn = conn;
		return 0;
	}
#endif

	bt_conn_set_state(conn, BT_CONN_CONNECT);

	err = bt_le_create_conn(conn);
	if (err) {
		conn->err = 0;
		bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
		bt_conn_unref(conn);
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
		bt_fsm_le_scan_update(false, bt_dev.fsm);
#else
		bt_le_scan_update(false);
#endif
		return err;
	}

	*ret_conn = conn;
	return 0;
}

#if !defined(CONFIG_BT_WHITELIST)
int bt_le_set_auto_conn(const bt_addr_le_t *addr,
			const struct bt_le_conn_param *param)
{
	struct bt_conn *conn;

	if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY)) {
		return -EAGAIN;
	}

	if (param && !bt_le_conn_params_valid(param)) {
		return -EINVAL;
	}

	if (!bt_le_scan_random_addr_check()) {
		return -EINVAL;
	}

	/* Only default identity is supported */
	conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr);
	if (!conn) {
		conn = bt_conn_add_le(BT_ID_DEFAULT, addr);
		if (!conn) {
			return -ENOMEM;
		}
	}

	if (param) {
		bt_conn_set_param_le(conn, param);

		if (!atomic_test_and_set_bit(conn->flags,
					     BT_CONN_AUTO_CONNECT)) {
			bt_conn_ref(conn);
		}
	} else {
		if (atomic_test_and_clear_bit(conn->flags,
					      BT_CONN_AUTO_CONNECT)) {
			bt_conn_unref(conn);
			if (conn->state == BT_CONN_CONNECT_SCAN) {
				bt_conn_set_state(conn, BT_CONN_DISCONNECTED);
			}
		}
	}

	if (conn->state == BT_CONN_DISCONNECTED &&
	    atomic_test_bit(bt_dev.flags, BT_DEV_READY)) {
		if (param) {
			bt_conn_set_state(conn, BT_CONN_CONNECT_SCAN);
		}
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
		bt_fsm_le_scan_update(false, bt_dev.fsm);
#else
		bt_le_scan_update(false);
#endif
	}

	bt_conn_unref(conn);

	return 0;
}
#endif /* !defined(CONFIG_BT_WHITELIST) */
#endif /* CONFIG_BT_CENTRAL */

int bt_conn_le_conn_update(struct bt_conn *conn,
			   const struct bt_le_conn_param *param)
{
#if !(defined(CONFIG_BT_USE_HCI_API) && CONFIG_BT_USE_HCI_API)
	struct hci_cp_le_conn_update *conn_update;
	struct net_buf *buf;

	if (conn->state != BT_CONN_CONNECTED) {
		return -ENOTCONN;
	}

	buf = bt_hci_cmd_create(BT_HCI_OP_LE_CONN_UPDATE,
				sizeof(*conn_update));
	if (!buf) {
		return -ENOBUFS;
	}

	conn_update = net_buf_add(buf, sizeof(*conn_update));
	(void)memset(conn_update, 0, sizeof(*conn_update));
	conn_update->handle = sys_cpu_to_le16(conn->handle);
	conn_update->conn_interval_min = sys_cpu_to_le16(param->interval_min);
	conn_update->conn_interval_max = sys_cpu_to_le16(param->interval_max);
	conn_update->conn_latency = sys_cpu_to_le16(param->latency);
	conn_update->supervision_timeout = sys_cpu_to_le16(param->timeout);
#if defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE
	return bt_hci_cmd_send_cb(BT_HCI_OP_LE_CONN_UPDATE, buf, NULL);
#else
	return bt_hci_cmd_send_sync(BT_HCI_OP_LE_CONN_UPDATE, buf, NULL);
#endif
#else
	return hci_api_le_conn_updata(conn->handle,
									param->interval_min,
									param->interval_max,
									param->latency,
									param->timeout, 0, 0);
#endif
}

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *bt_conn_create_frag_timeout_debug(size_t reserve,
						  k_timeout_t timeout,
						  const char *func, int line)
#else
struct net_buf *bt_conn_create_frag_timeout(size_t reserve, k_timeout_t timeout)
#endif
{
	struct net_buf_pool *pool = NULL;

#if CONFIG_BT_L2CAP_TX_FRAG_COUNT > 0
	pool = &frag_pool;
#endif

#if defined(CONFIG_NET_BUF_LOG)
	return bt_conn_create_pdu_timeout_debug(pool, reserve, timeout,
						func, line);
#else
	return bt_conn_create_pdu_timeout(pool, reserve, timeout);
#endif /* CONFIG_NET_BUF_LOG */
}

#if defined(CONFIG_NET_BUF_LOG)
struct net_buf *bt_conn_create_pdu_timeout_debug(struct net_buf_pool *pool,
						 size_t reserve,
						 k_timeout_t timeout,
						 const char *func, int line)
#else
struct net_buf *bt_conn_create_pdu_timeout(struct net_buf_pool *pool,
					   size_t reserve, k_timeout_t timeout)
#endif
{
	struct net_buf *buf;

	/*
	 * PDU must not be allocated from ISR as we block with 'K_FOREVER'
	 * during the allocation
	 */
	__ASSERT_NO_MSG(!k_is_in_isr());

	if (!pool) {
		pool = &acl_tx_pool;
	}

	if (IS_ENABLED(CONFIG_BT_DEBUG_CONN)) {
#if defined(CONFIG_NET_BUF_LOG)
		buf = net_buf_alloc_fixed_debug(pool, K_NO_WAIT, func, line);
#else
		buf = net_buf_alloc(pool, K_NO_WAIT);
#endif
		if (!buf) {
			//BT_WARN("Unable to allocate buffer with K_NO_WAIT");
#if defined(CONFIG_NET_BUF_LOG)
			buf = net_buf_alloc_fixed_debug(pool, timeout, func,
							line);
#else
			buf = net_buf_alloc(pool, timeout);
#endif
		}
	} else {
#if defined(CONFIG_NET_BUF_LOG)
		buf = net_buf_alloc_fixed_debug(pool, timeout, func,
							line);
#else
		buf = net_buf_alloc(pool, timeout);
#endif
	}

	if (!buf) {
#if !(defined(CONFIG_BT_HOST_OPTIMIZE) && CONFIG_BT_HOST_OPTIMIZE)
		BT_ERR("Unable to allocate buffer within timeout\n");
#endif
		return NULL;
	}

	reserve += sizeof(struct bt_hci_acl_hdr) + BT_BUF_RESERVE;
	net_buf_reserve(buf, reserve);

	return buf;
}

#if defined(CONFIG_BT_SMP) || defined(CONFIG_BT_BREDR)
int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb)
{
	if (!cb) {
		bt_auth = NULL;
		return 0;
	}

	if (bt_auth) {
		return -EALREADY;
	}

	/* The cancel callback must always be provided if the app provides
	 * interactive callbacks.
	 */
	if (!cb->cancel &&
	    (cb->passkey_display || cb->passkey_entry || cb->passkey_confirm ||
#if defined(CONFIG_BT_BREDR)
	     cb->pincode_entry ||
#endif
	     cb->pairing_confirm)) {
		return -EINVAL;
	}

	bt_auth = cb;
	return 0;
}

int bt_conn_auth_passkey_entry(struct bt_conn *conn, unsigned int passkey)
{
	if (!bt_auth) {
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_BT_SMP) && conn->type == BT_CONN_TYPE_LE) {
		bt_smp_auth_passkey_entry(conn, passkey);
		return 0;
	}

#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR) {
		/* User entered passkey, reset user state. */
		if (!atomic_test_and_clear_bit(conn->flags, BT_CONN_USER)) {
			return -EPERM;
		}

		if (conn->br.pairing_method == PASSKEY_INPUT) {
			return ssp_passkey_reply(conn, passkey);
		}
	}
#endif /* CONFIG_BT_BREDR */

	return -EINVAL;
}

int bt_conn_auth_passkey_confirm(struct bt_conn *conn)
{
	if (!bt_auth) {
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_BT_SMP) &&
	    conn->type == BT_CONN_TYPE_LE) {
		return bt_smp_auth_passkey_confirm(conn);
	}

#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR) {
		/* Allow user confirm passkey value, then reset user state. */
		if (!atomic_test_and_clear_bit(conn->flags, BT_CONN_USER)) {
			return -EPERM;
		}

		return ssp_confirm_reply(conn);
	}
#endif /* CONFIG_BT_BREDR */

	return -EINVAL;
}

int bt_conn_auth_cancel(struct bt_conn *conn)
{
	if (!bt_auth) {
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_BT_SMP) && conn->type == BT_CONN_TYPE_LE) {
		return bt_smp_auth_cancel(conn);
	}

#if defined(CONFIG_BT_BREDR)
	if (conn->type == BT_CONN_TYPE_BR) {
		/* Allow user cancel authentication, then reset user state. */
		if (!atomic_test_and_clear_bit(conn->flags, BT_CONN_USER)) {
			return -EPERM;
		}

		switch (conn->br.pairing_method) {
		case JUST_WORKS:
		case PASSKEY_CONFIRM:
			return ssp_confirm_neg_reply(conn);
		case PASSKEY_INPUT:
			return ssp_passkey_neg_reply(conn);
		case PASSKEY_DISPLAY:
			return bt_conn_disconnect(conn,
						  BT_HCI_ERR_AUTH_FAIL);
		case LEGACY:
			return pin_code_neg_reply(&conn->br.dst);
		default:
			break;
		}
	}
#endif /* CONFIG_BT_BREDR */

	return -EINVAL;
}

int bt_conn_auth_pairing_confirm(struct bt_conn *conn)
{
	if (!bt_auth) {
		return -EINVAL;
	}

	switch (conn->type) {
#if defined(CONFIG_BT_SMP)
	case BT_CONN_TYPE_LE:
		return bt_smp_auth_pairing_confirm(conn);
#endif /* CONFIG_BT_SMP */
#if defined(CONFIG_BT_BREDR)
	case BT_CONN_TYPE_BR:
		return ssp_confirm_reply(conn);
#endif /* CONFIG_BT_BREDR */
	default:
		return -EINVAL;
	}
}
#endif /* CONFIG_BT_SMP || CONFIG_BT_BREDR */

u8_t bt_conn_index(struct bt_conn *conn)
{
	u8_t index = conn - conns;

	__ASSERT(index < CONFIG_BT_MAX_CONN, "Invalid bt_conn pointer");
	return index;
}

struct bt_conn *bt_conn_lookup_index(u8_t index)
{
	struct bt_conn *conn;

	if (index >= ARRAY_SIZE(conns)) {
		return NULL;
	}

	conn = &conns[index];

	if (!atomic_get(&conn->ref)) {
		return NULL;
	}

	return bt_conn_ref(conn);
}

int bt_conn_init(void)
{
	int err, i;

    k_fifo_init(&free_tx);

	for (i = 0; i < ARRAY_SIZE(conn_tx); i++) {
		k_fifo_put(&free_tx, &conn_tx[i]);
	}

	bt_att_init();

	err = bt_smp_init();
	if (err) {
		return err;
	}

	bt_l2cap_init();

    NET_BUF_POOL_INIT(acl_tx_pool);
    NET_BUF_POOL_INIT(frag_pool);

	/* Initialize background scan */
	if (IS_ENABLED(CONFIG_BT_CENTRAL)) {
		for (i = 0; i < ARRAY_SIZE(conns); i++) {
			struct bt_conn *conn = &conns[i];

			if (!atomic_get(&conn->ref)) {
				continue;
			}

#if !defined(CONFIG_BT_WHITELIST)
			if (atomic_test_bit(conn->flags,
					    BT_CONN_AUTO_CONNECT)) {
				/* Only the default identity is supported */
				conn->id = BT_ID_DEFAULT;
				bt_conn_set_state(conn, BT_CONN_CONNECT_SCAN);
			}
#endif /* !defined(CONFIG_BT_WHITELIST) */
		}
	}

	return 0;
}
