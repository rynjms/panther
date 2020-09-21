import mixpanel from 'mixpanel-browser';
import { DestinationTypeEnum } from 'Generated/schema';
import storage from 'Helpers/storage';
import { ANALYTICS_CONSENT_STORAGE_KEY } from 'Source/constants';

// TODO: Pending backend to work
const mixpanelPublicToken = process.env.MIXPANEL_PUBLIC_TOKEN;

const envCheck =
  mixpanelPublicToken &&
  // TODO: Pending backend to work
  storage.local.read<boolean>(ANALYTICS_CONSENT_STORAGE_KEY) &&
  process.env.NODE_ENV === 'production';

if (envCheck) mixpanel.init(mixpanelPublicToken);

enum TrackEventEnum {
  'choose-destination-to-create' = 'Choose Destination to create',
  'added-destination' = 'Added Destination',
  'added-rule' = 'Added Rule',
  'success-sign-in' = 'Successful Sign in',
}

enum TrackErrorEnum {
  'failed-to-add-destination' = 'Failed to create destination',
  'failed-to-create-rule' = 'Failed to create Rule',
  'failed-mfa' = 'Failed MFA',
}

enum TrackPageViewEnum {
  'log-analysis-overview' = 'Log Analysis Overview',
}

type srcType = 'destinations';
type ctxType = DestinationTypeEnum;

interface TrackPageViewProps {
  name: keyof typeof TrackPageViewEnum;
}

interface TrackEventProps {
  name: keyof typeof TrackEventEnum;
  src?: srcType;
  ctx?: ctxType;
}

interface TrackErrorProps {
  name: keyof typeof TrackErrorEnum;
  src?: srcType;
  ctx?: ctxType;
  data?: any;
}
// interface
const actions = {
  identify: id => {
    if (envCheck) mixpanel.identify(id);
  },
  alias: id => {
    if (envCheck) mixpanel.alias(id);
  },
  people: {
    set: props => {
      if (envCheck) mixpanel.people.set(props);
    },
  },
  // TODO: Above functions are not used for the moment, either utilize or remove
  pageView: ({ name }: TrackPageViewProps) => {
    if (envCheck) mixpanel.track(TrackPageViewEnum[name], { type: 'pageview' });
  },
  track: ({ name, src, ctx }: TrackEventProps) => {
    if (envCheck) mixpanel.track(TrackEventEnum[name], { type: 'event', src, ctx });
  },
  error: ({ name, src, ctx, data }: TrackErrorProps) => {
    if (envCheck) mixpanel.track(TrackErrorEnum[name], { type: 'error', src, ctx, data });
  },
};

export default actions;
