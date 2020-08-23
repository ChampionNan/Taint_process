from tqdm import tqdm
from fuzzywuzzy import fuzz, process
import subprocess
import time

Sources = ['url', 'untainted', 'cookie', 'urlHostname', 'urlOrigin', 'storage', 'urlPathname', 'message', 'windowname', 'referrer', 'urlSearch']
Sink_type = ['anchorSrcSink', 'scriptSrcUrlSink', 'imgSrcSink', 'cookie', 'iframeSrcSink', 'javascript', 'html']
target_sink = ['html', 'javascript', 'eventhandler']
target_source = ['url', 'urlHostname', 'urlOrigin', 'urlPathname', 'urlSearch', 'urlHost', 'urlHash']

def Read_record():
    count = 0
    stage = 0
    content_list = []
    total_content_list = []
    sink_func = ''
    sinkType = ''
    msgid_content = {}
    sinkType_list = []
    taintSource_flag = False
    Sink_type_flag = False
    taintSource = []
    f = open('record_15863_1597312437433_0')
    lines = f.readlines()
    for (index, line) in enumerate(lines):
        line = line.strip().replace('\"', '"').replace("\'", "'").replace("\\\'", "'").replace('\\\"', '"')
        # start
        if line == '( message = (':
            stage = 0.5
            taintSource_flag = False
            Sink_type_flag = False
            taintSource = []
        # taintSource
        if stage == 0.5 and 'taintSource = (' in line:
            stage = 0.6
        if stage == 0.6 and 'type = ' in line:
            start_index = line.index('type = ')
            end_index = 0
            if 'encoding' in line:
                end_index = line.index('encoding')-2
            else:
                end_index = line.rindex(',')
            label = line[start_index+len('type = '):end_index]
            if label in target_source:
                taintSource_flag = True
                if label not in taintSource:
                    taintSource.append(label)
        # next stage
        if stage == 0.6 and 'targetString =' in line:
            stage = 1
        # append content
        if stage == 1 and 'content = ' in line:
            start_index = line.find('content = ')
            end_index = line.rfind('\",')
            content = str(line[start_index+len('content = ')+1:end_index])
            content_list.append(content)
        # judge js type
        # if stage == 1 and 'sinkType = javascript' in line:
        if stage == 1 and 'sinkType = ' in line:
            stage = 2
            count = count + 1
            start_index = line.index('=')
            end_index = line.rindex(',')
            sinkType = line[start_index+2:end_index]
            if sinkType not in Sink_type:
                Sink_type.append(sinkType)
            sinkType_list.append(line[start_index+2:])
            if sinkType in target_sink:
                Sink_type_flag = True
        # find sink type
        if stage == 2 and 'stackTrace = ' in line:
            if '0: builtin exit frame: ' in line:
                stage = 3
                start_index = line.find('0: builtin exit frame: ')
                end_index = line.find('1:')
                sink_func = line[start_index + len('0: builtin exit frame: '):end_index]
                sink_func = sink_func.strip()
            if '0: builtin exit frame: ' not in line:
                sink_func = 'unknown'
                stage = 3

        if (stage == 3 and 'messageId = ' in line) and (taintSource_flag == True) and (Sink_type_flag == True):
            start_index = line.find('messageId = ')
            end_index = line.rfind('\",')
            msgid = int(line[start_index+len('messageId = '):end_index])
            #print('message id: ', msgid)
            msgid_content[msgid] = ["".join(content_list), sinkType, sink_func, taintSource]
            total_content_list.append("".join(content_list))
        # end
        if line == 'contextId = (':
            stage = 0
            content_list = []

    return msgid_content, count, total_content_list, sinkType_list

def output(data):
    index = 0
    with open('find_proper_record.txt', 'w+') as fp:
        # msgid_content[msgid] = ["".join(content_list), sinkType, sink_func, taintSource]
        for key, value in results.items():
            # print(value[0])
            fp.write('# '+str(index))
            fp.write('\n')
            fp.write('message id:')
            fp.write('\n')
            fp.write(str(key))
            fp.write('\n')
            fp.write('sinkType: ')
            fp.write('\n')
            fp.write(str(value[1]))
            fp.write('\n')
            fp.write("taintSource: ")
            fp.write('\n')
            fp.write(str(value[3]))
            fp.write('\n')
            fp.write("sink function: ")
            fp.write('\n')
            fp.write(str(value[2]))
            fp.write('\n')
            fp.write('content: ')
            fp.write('\n')
            fp.write(str(value[0]))
            fp.write('\n')
            fp.write('\n')
            index = index + 1

def find_eachinfo(all_content):
    f = open('filiter_result_15863.txt')
    lines = f.readlines()
    #print("lines: ", len(lines))
    #for line in lines:
    for i in tqdm(range(0, len(lines))):
        cmp_str = []
        if 'total number of flows' not in lines[i]:
            save_line = lines[i]
            start_index = lines[i].index(":")
            lines[i] = lines[i][start_index + 1:]
            lines[i] = eval(lines[i])
            print(lines[i], type(lines[i]))
            part = lines[i][len(lines[i])-1]
            message = part[1]
            if 'Sink_function' in message[0]:
                cmp_str.append(message[1])
            find_similar(all_content, cmp_str, save_line)
            cmp_str = []
            '''
            for part in lines[i]:
                message = part[1]
                # print("MSG: ", message)
                if 'Sink_function' in message[0]:
                    cmp_str.append(message[1])
                to_index = message.index('to')
                from_index = message.index('from')
                # to
                dest_info, dest = ' '.join(message[to_index + 1:from_index]).split('|', 1)
                # from
                source_info, source = ' '.join(message[from_index + 1:len(message) + 1]).split('|', 1)
                # from (to from to from) to
                # from ( ...
                if part == lines[i][0]:
                    cmp_str.append(source)

                cmp_str.append(dest)
            '''

count = 0

def find_similar(all_content, target, save_line, threhold = 70):
    # all_content: standard, target: find some similar part in target
    choices = all_content
    top2pair = []
    global count
    for msgid, each in choices.items():
        result = process.extract(each[0], target, limit=1, scorer=fuzz.ratio)
        #print('Result: ', result[0][1])
        # print("Score: ", result)
        # ["message id", msgid, record source:, each[0] , "sinkType: ", each[1], "sink function: ", each[2], "taintSource_list: ", each[3], "log resource: ", save_line, "score: ", result]
        if result[0][1] >= threhold:
            top2pair.append([msgid, each[0], each[1], each[2], each[3], save_line, result[0][1]])
        # if result[0][1] >= threhold:
            #top2pair[each] = result
            # top2pair[msgid] = ("record source: ", each[0], "sinkType: ", each[1], "sink function: ", each[2], "taintSource_list: ", each[3], "log resource: ", save_line, "score: ", result)
    if top2pair:
        with open('pair_result.txt', 'a+') as f:
            for value in top2pair:
                f.write('# ' + str(count))
                f.write('\n')
                f.write("similar score: ")
                f.write('\n')
                f.write(str(value[6]))
                f.write('\n')
                f.write("message id: ")
                f.write('\n')
                f.write(str(value[0]))
                f.write('\n')
                f.write("sinkType: ")
                f.write('\n')
                f.write(str(value[2]))
                f.write('\n')
                f.write("sink function: ")
                f.write('\n')
                f.write(str(value[3]))
                f.write('\n')
                f.write("taintSource_list: ")
                f.write('\n')
                f.write(str(value[4]))
                f.write('\n')
                f.write('record source: ')
                f.write('\n')
                f.write(str(value[1]))
                f.write('\n')
                f.write("log resource: ")
                f.write('\n')
                f.write(str(value[5]))
                f.write('\n')
                f.write('\n')
                count = count + 1

if __name__ == '__main__':
    start = time.time()
    try:
        cmd = 'rm pair_result.txt'
        subprocess.run(cmd.split(' '), check=True)
    except Exception as e:
        pass
    # global count
    results, contend_count, all_content, sinkType_list = Read_record()
    output(results)
    #print('All content: ')
    #for index, cont in enumerate(all_content):
     #   print(index, ": ", cont)

    print('All content length: ', len(all_content))
    find_eachinfo(results)
    print('count: ')
    print(count)
    end = time.time()
    print('Runtime: ', (end-start)/60, 'minute')



