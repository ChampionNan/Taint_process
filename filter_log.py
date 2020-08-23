from tqdm import tqdm
import subprocess
listeners = ['OnNewSubStringCopy', 'OnNewSlicedString', 'OnNewConcatStringCopy', 'NewConsString', 'OnNewFromJsonString', 'OnNewReplaceRegexpWithString', 'OnJoinManyStrings', 'ConvertCase']
sink_header = 'Sink_function:'
sink_function = ['document.write', 'document.writeln', 'window.document.write', 'window.document.writeln', 'document.setCookie', 'element.setAttributeon',
                 'element.setAttributecaseAdjustedLocalName', 'element.attributeChanged', 'element.setInnerHTML', 'element.setOuterHTML', 'element.insertAdjacentHTML',
                 'setTimeout', 'setTimeoutno', 'setInterval', 'setIntervalno', 'Location.setLocation', 'HTMLAnchorElement.parseAttribute', 'HTMLEmbedElement.parseAttribute',
                 'HTMLIFrameElement.parseAttribute', 'HTMLImageElement.parseAttribute', 'HTMLScriptElement.parseAttribute', 'HTMLScriptElement.setText']
sink = [sink_header + x for x in sink_function] + ['Sink']

Taint_info = [4, 5, 7, 8, 9, 11, 12]

def ReadFile():
    f = open("log_file2")
    lines = f.readlines()
    data = {}
    data_sink = {}
    array_flag = 0
    array_prior_msg = []
    for (index, line) in enumerate(lines):
        # print('Line before: ', line)
        line = line.replace('\n', '').replace('\r', '').replace('|c', '|').replace('\"', '')
        line = line.split(' ')
        # print('Line after: ', line)
        if line[0] in listeners and line[0] != 'OnJoinManyStrings' and array_flag == 0:
            data[index] = line
        elif line[0] in sink:
            # eval sink func
            sink_from = ''
            if line[0] == 'Sink':
                sink_from = ' '.join(line[6:])
                sink_from = sink_from[:len(sink_from)-1] # delete <
                data_sink[index] = 'Sink_function:eval ' + sink_from
            else:
                #sink_from = eval(' '.join(line[2:]).split('|', 1)[1])
                sink_from = ' '.join(line[2:]).split('|', 1)[1]
                data_sink[index] = line[0] + ' ' + sink_from

        elif line[0] == 'OnJoinManyStrings':
            array_flag = 1
            array_prior_msg = line[0:4]
            # print('array_prior_msg: ', array_prior_msg)
        elif array_flag != 0 and array_flag != 9:
            array_flag = array_flag + 1
        elif array_flag == 9:
            if line[1] == '}':
                array_flag = 0
            else:
                from_msg = line[len(line)-1]
                # print('from_msg: ', from_msg)
                from_msg = from_msg[0:len(from_msg)-1]
                from_tag = array_prior_msg[2].split('|')[0]
                from_final = from_tag + '|' + from_msg
                # print('from_final', from_final)
                each_join_array_msg = array_prior_msg + [from_final]
                # print('Final each join array msg: ', each_join_array_msg)
                data[index] = each_join_array_msg

    # print('Data: ', data)
    # data = data.replace('\"', '\'')
    return data, data_sink

def JudgeFlow(flows, key, value):
    '''
    :param flows: find taint flow
    :param key: insert flow line index
    :param value: insert flow value to match
    :return: changed flows
    '''
    # match each
	# print('in JudgeFlow')
    if flows :
        #print("flows:", flows)
        for flow in flows:
            try:
                from_index = value.index("from")
                to_index = value.index("to")
                # target_info, target_content = value[4].split('|')
                target_info, target_content = ' '.join(value[from_index + 1:len(value)]).split('|', 1)
                # print('target_info: ', target_info, 'target_content: ', target_content)
                # source_info, source_content = flow[len(flow) - 1][1][2].split('|')  # last part of certain flows
                source_info, source_content = ' '.join(flow[len(flow) - 1][1][to_index + 1:from_index]).split('|', 1)
                if target_info == source_info and target_content == source_content and (int(target_info) in Taint_info):
                #if target_info == source_info and target_content == source_content:
                    flow.append([key, value])
                    return flows
            except: continue
        flows.append([[key, value]])
        return flows
        # empty/not found proper flow to add
    else:
        flows.append([[key,value]])
    return flows

def GetFlow(data):
    flows = []
    index = 1
    print('in GetFlow', 'data length:', len(data))
    i = 0
    for key, value in tqdm(data.items()):
        # for key, value in each.items():
        # OnNewSubStringCopy from 8|c"https://www.google.com" to 8|"https://www.google.com" 0 22
		# print('Index:', i)
        if value[0] in listeners:
            #print("key:", key, "value:", value)
            flows = JudgeFlow(flows, key, value)
        i = i + 1
    return flows

def Sink_flow(data, data_sink):
    real_taint = []
    # print('Data sink: ', data_sink)
    for key, each_sink in data_sink.items():
        for flow in data:
            try:
                # end_part = flow[len(flow) - 1][1][2].split('|', 1)[1]
                end_part = flow[len(flow) - 1][1]
                to_index = end_part.index('to')
                from_index = end_part.index('from')
                listener_part = ' '.join(end_part[2:from_index]).split('|', 1)[1]
                # print('listener_part: ', listener_part)
                sink_from = each_sink.split(' ')[1]
                if listener_part == sink_from:
                    flow.append([key, each_sink.split(' ')])
                    real_taint.append(flow)
                    # flush buffer
                    print('LEN: ', len(real_taint))
                    '''
                    if len(real_taint) > 20:
                        save2file(real_taint)
                        real_taint = {}'''
            except:
                pass
                # print("Error folw: ", flow)
                # return []

    return real_taint


def save2file(data):
    count = 0
    with open("log_filiter_result.txt", "a+") as fp:
        for item in data:
            # print('Count: ', count, 'Item: ', item)
            if len(item) > 2:
                fp.write(str(count))
                fp.write(":")
                fp.write(str(item))
                fp.write("\n")
                count = count + 1
        fp.write("total number of flows: ")
        fp.write(str(count))
        fp.close()
    print("real count:", count)

if __name__ == '__main__':
    try:
        cmd = 'rm filiter_result.txt'
        subprocess.run(cmd.split(' '), check=True)
    except Exception as e:
        pass
    data, data_sink = ReadFile()
    #print(data)
    data = GetFlow(data)
    print('no sink flow count: ', len(data))
    data = Sink_flow(data, data_sink)
    # print('All data', data)
    save2file(data)

'''
        # OnNewSlicedString target 2|"OGPC=19008563-3:"OnNewSlicedString first2|"1P_JAR=2020-07-14-03; OGPC=19008563-3:" 22 16
        elif value[0] == listeners[1]:
        # OnNewConcatStringCopy dest 0|"https:"OnNewConcatStringCopy first 4|"https" second 0|#:
        #elif value[0] == listeners[2]:
        # NewConsString target 8|c";domain=google.com" first 0|#;domain= second 8|"google.com"
        elif value[0] == listeners[3]:
        # OnNewFromJsonString target ttype|xxx source stype|xxx
        elif value[0] == listeners[4]:
        # OnNewReplaceRegexpWithString subject stype|xxx result rtype|xxx
        elif value[0] == listeners[5]:
        # ConvertCase from stype|xxx to atype|xxx
        elif value[0] == listeners[7]:
        '''
