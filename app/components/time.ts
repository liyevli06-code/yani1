export type CalendarDiff = {
  years: number;
  months: number;
  days: number;
  hours: number;
  minutes: number;
  /** True when `target` is already in the past relative to `from`. */
  past: boolean;
};

/**
 * Calendar-accurate breakdown of the time between two dates, into years/months/days/
 * hours/minutes — accounting for actual month lengths rather than averaging days.
 */
export function calendarDiff(target: Date, from: Date): CalendarDiff | null {
  if (Number.isNaN(target.getTime())) return null;

  const past = target.getTime() < from.getTime();
  let a = past ? target : from;
  let b = past ? from : target;

  let years = b.getFullYear() - a.getFullYear();
  let months = b.getMonth() - a.getMonth();
  let days = b.getDate() - a.getDate();
  let hours = b.getHours() - a.getHours();
  let minutes = b.getMinutes() - a.getMinutes();

  if (minutes < 0) {
    minutes += 60;
    hours -= 1;
  }
  if (hours < 0) {
    hours += 24;
    days -= 1;
  }
  if (days < 0) {
    const daysInPrevMonth = new Date(b.getFullYear(), b.getMonth(), 0).getDate();
    days += daysInPrevMonth;
    months -= 1;
  }
  if (months < 0) {
    months += 12;
    years -= 1;
  }

  return { years, months, days, hours, minutes, past };
}
