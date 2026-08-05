package main

import (
	"strings"
	"time"
)

const (
	defaultGeneratedHTMLReportLang = "en"
	reportTimestampDisplayLayout   = "2006-01-02 15:04 UTC"
	reportTimestampParseLayout     = "2006-01-02 15:04"
)

const generatedHTMLReportLocaleScript = `<script>
(function(){
  function reportLocale(){
    if(navigator.languages && navigator.languages.length){return navigator.languages;}
    if(navigator.language){return navigator.language;}
    var lang=document.documentElement.getAttribute('lang');
    return lang || undefined;
  }
  function rememberFallback(node){
    if(node && !node.hasAttribute('data-fallback-text')){
      node.setAttribute('data-fallback-text',node.textContent || '');
    }
  }
  function formatTimes(){
    if(typeof Intl === 'undefined' || !Intl.DateTimeFormat){return;}
    var formatter;
    try{
      formatter=new Intl.DateTimeFormat(reportLocale(),{dateStyle:'medium',timeStyle:'short',timeZoneName:'short'});
    }catch(_){return;}
    document.querySelectorAll('time[data-report-time][datetime]').forEach(function(node){
      var value=node.getAttribute('datetime');
      if(!value){return;}
      var date=new Date(value);
      if(isNaN(date.getTime())){return;}
      rememberFallback(node);
      node.textContent=formatter.format(date);
    });
  }
  function formatDurations(){
    if(typeof Intl === 'undefined' || !Intl.NumberFormat){return;}
    document.querySelectorAll('[data-report-duration][data-duration-ms]').forEach(function(node){
      var ms=Number(node.getAttribute('data-duration-ms'));
      if(!isFinite(ms) || ms <= 0){return;}
      var seconds=ms/1000;
      var unit=ms < 1000 ? 'ms' : 's';
      var value=ms < 1000 ? ms : seconds;
      var digits=ms < 1000 || seconds >= 10 ? 0 : 1;
      var formatter;
      try{
        formatter=new Intl.NumberFormat(reportLocale(),{maximumFractionDigits:digits});
      }catch(_){return;}
      rememberFallback(node);
      node.textContent=formatter.format(value)+' '+unit;
    });
  }
  formatTimes();
  formatDurations();
})();
</script>`

func formatReportTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(reportTimestampDisplayLayout)
}

func formatReportTimestampDateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func reportTimestampDateTime(display, dateTime string) string {
	dateTime = strings.TrimSpace(dateTime)
	if dateTime != "" {
		return dateTime
	}
	display = strings.TrimSpace(display)
	if display == "" {
		return ""
	}
	if strings.HasSuffix(display, " UTC") {
		t, err := time.ParseInLocation(reportTimestampParseLayout, strings.TrimSuffix(display, " UTC"), time.UTC)
		if err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	if t, err := time.Parse(time.RFC3339, display); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return ""
}
