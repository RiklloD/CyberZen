import { cronJobs } from 'convex/server'
import { internal } from './_generated/api'

const crons = cronJobs()

crons.interval(
  'sync recent advisories',
  { hours: 6 },
  internal.breachIngest.syncRecentAdvisoriesOnSchedule,
  {
    maxRepositories: 20,
    lookbackHours: 72,
    githubLimit: 100,
    osvLimit: 100,
  },
)

export default crons
