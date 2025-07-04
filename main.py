import crawler
from DownloadServer import virusInspection
import ocrLLMProcess
import gpt_report

#로컬용
if __name__=="__main__":
    mainroot = '/opt/isolation'
    print("키워드를 입력하세요 : ")

    keyword = input()

    print(keyword)
    print(type(keyword))

    # #1차    
    if keyword == '':
        crawler.pageSelenium(keyword)
    else:
        crawler.grayhatApi(keyword)
        crawler.pageSelenium(keyword)

    crawler.crawledPageDataInsert()

    # #2차
    virusInspection.main(mainroot)
   

    #3차
    ocrLLMProcess.main(mainroot)


    # #최종
    gpt_report.run_pipeline(keyword)
