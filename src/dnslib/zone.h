/*!
 * \file zone.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone structure and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_ZONE_H_
#define _CUTEDNS_DNSLIB_ZONE_H_

#include "node.h"
#include "dname.h"

/*----------------------------------------------------------------------------*/

struct dnslib_zone {
	dnslib_node_t *apex;
};

typedef struct dnslib_zone dnslib_zone_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new DNS zone.
 *
 * \param apex Node representing the zone apex.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex);

/*!
 * \brief Add a node to the given zone.
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval 0 on success.
 * \retval -1 if an error occured.
 */
int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
dnslib_node_t *dnslib_zone_get_node(dnslib_zone_t *zone,
                                    const dnslib_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \note This function is identical to dnslib_zone_get_node(), only it returns
 *       constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const dnslib_node_t *dnslib_zone_find_node(dnslib_zone_t *zone,
                                           const dnslib_dname_t *name);

/*!
 * \brief Correctly deallocates the zone structure and possibly all its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 * \param free_nodes If 0, the nodes will not be deleted, if <> 0, all nodes
 *                   in the zone are deleted using dnslib_node_free().
 */
void dnslib_zone_free(dnslib_zone_t **zone, int free_nodes);

#endif

/*! @} */
