/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import { Text, Flex, Icon, AbstractButton, Box, Collapse, useSnackbar } from 'pouncejs';
import { AlertDetails, ListDestinations } from 'Pages/AlertDetails';
import last from 'lodash/last';
import AlertDeliveryTable from './AlertDeliveryTable';
import { useRetryAlertDelivery } from './graphql/retryAlertDelivery.generated';

interface AlertDeliverySectionProps {
  alert: AlertDetails['alert'];
  alertDestinations: ListDestinations['destinations'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({
  alert,
  alertDestinations,
}) => {
  const [isHistoryVisible, setHistoryVisibility] = React.useState(false);

  const { pushSnackbar } = useSnackbar();
  const [retryAlertDelivery] = useRetryAlertDelivery({
    update: (cache, { data }) => {
      const dataId = cache.identify({
        __typename: 'AlertDetails',
        alertId: data.deliverAlert.alertId,
      });

      cache.modify(dataId, {
        deliveryResponses: () => data.deliverAlert.deliveryResponses,
      });
    },
    onError: () => pushSnackbar({ variant: 'error', title: 'Failed to deliver alert' }),
    onCompleted: data => {
      const attemptedDelivery = last(data.deliverAlert.deliveryResponses);
      if (attemptedDelivery.success) {
        pushSnackbar({ variant: 'success', title: 'Successfully delivered alert' });
      } else {
        pushSnackbar({ variant: 'error', title: 'Failed to deliver alert' });
      }
    },
  });

  const onAlertDeliveryRetry = React.useCallback(
    (outputId: string) => {
      retryAlertDelivery({
        variables: {
          input: {
            alertId: alert.alertId,
            outputIds: [outputId],
          },
        },
      });
    },
    [retryAlertDelivery, alert]
  );

  // FIXME: `alertDestinations` should be part of Alert & coming directly from GraphQL
  //  Someday...
  const { deliveryResponses } = alert;
  const enhancedAndSortedAlertDeliveries = React.useMemo(() => {
    return deliveryResponses
      .reduce((acc, dr) => {
        const dest = alertDestinations.find(d => d.outputId === dr.outputId);
        if (dest) {
          acc.push({
            ...dr,
            ...dest,
          });
        }
        return acc;
      }, [])
      .reverse();
  }, [deliveryResponses, alertDestinations]);

  if (!deliveryResponses.length || !enhancedAndSortedAlertDeliveries.length) {
    return (
      <Flex align="warning" spacing={4}>
        <Icon type="info" size="small" color="blue-400" />
        <Text fontWeight="medium">Delivery information could not be retrieved</Text>
      </Flex>
    );
  }

  const isMostRecentDeliverySuccessful = enhancedAndSortedAlertDeliveries[0].success;
  return (
    <Box>
      <Flex justify="space-between">
        {isMostRecentDeliverySuccessful ? (
          <Flex align="center" spacing={4}>
            <Icon type="check-circle" size="small" color="green-400" />
            <Text fontWeight="medium">Alert was delivered successfully</Text>
          </Flex>
        ) : (
          <Flex align="center" spacing={4}>
            <Icon type="alert-circle" size="small" color="red-300" />
            <Text fontWeight="medium" color="red-300">
              Alert delivery failed
            </Text>
          </Flex>
        )}
        <AbstractButton
          fontSize="medium"
          color="teal-400"
          _hover={{ color: 'teal-300' }}
          onClick={() => setHistoryVisibility(!isHistoryVisible)}
        >
          {isHistoryVisible ? 'Hide History' : 'Show History'}
        </AbstractButton>
      </Flex>
      <Collapse open={isHistoryVisible}>
        <Box backgroundColor="navyblue-400" mt={6}>
          <AlertDeliveryTable
            alertDeliveries={enhancedAndSortedAlertDeliveries}
            onAlertDeliveryRetry={onAlertDeliveryRetry}
          />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
