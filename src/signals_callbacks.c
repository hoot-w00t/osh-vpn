#include "signals_callbacks.h"
#include "oshd.h"
#include "logger.h"
#include <stdlib.h>

// Call oshd_stop() to close all connections and exit
// If oshd.run is false oshd_stop() was called before, force close with exit()
void oshd_signal_exit(void)
{
    if (oshd.run) {
        logger_debug(DBG_SIGNALS, "Received exit signal");
        oshd_stop();
    } else {
        logger(LOG_CRIT, "Received another exit signal, force-exiting");
        exit(EXIT_FAILURE);
    }
}

// Dump the digraph of the network to stdout
void oshd_signal_digraph(void)
{
    logger_debug(DBG_SIGNALS, "Received digraph signal");
    node_tree_dump_digraph();
}
