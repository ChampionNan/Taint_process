from tqdm import tqdm
import filter
import difflib
import copy
import subprocess

listeners = ['OnNewSubStringCopy', 'OnNewSlicedString', 'OnNewConcatStringCopy', 'NewConsString', 'OnNewFromJsonString', 'OnNewReplaceRegexpWithString', 'OnJoinManyStrings', 'ConvertCase']
sink_header = 'Sink_function:'
sink_function = ['document.write', 'document.writeln', 'window.document.write', 'window.document.writeln', 'document.setCookie', 'element.setAttributeon',
                 'element.setAttributecaseAdjustedLocalName', 'element.attributeChanged', 'element.setInnerHTML', 'element.setOuterHTML', 'element.insertAdjacentHTML',
                 'setTimeout', 'setTimeoutno', 'setInterval', 'setIntervalno', 'Location.setLocation', 'HTMLAnchorElement.parseAttribute', 'HTMLEmbedElement.parseAttribute',
                 'HTMLIFrameElement.parseAttribute', 'HTMLImageElement.parseAttribute', 'HTMLScriptElement.parseAttribute', 'HTMLScriptElement.setText']
sink = [sink_header + x for x in sink_function] + ['Sink']

special_word = ['*', '.', '?', '+', '$', '^', '[', ']', '(', ')', '{', '}', '|', '\\', '/']
array_dest = ''
array_source = []
array_flag = 0
array_param = ''
trans_number = 0

def transflow(linenumber, eachline):
    '''Transform each taint flow'''
    # each block in one taint flow
    # eachline = eachline[2:]
    global array_dest
    global array_source
    global array_flag
    global array_param
    global trans_number
    for (index, part_flow) in enumerate(eachline):
        info = part_flow
        print('info: ', info)
        message = info[1]
        print('message: ', message)
        listener = message[0]
        print('listener: ', listener)
        if listener in listeners:
            to_index = message.index('to')
            from_index = message.index('from')
            print('to_index: ', to_index, 'from_index: ', from_index)
            dest_info, dest = ' '.join(message[to_index + 1:from_index]).split('|', 1)
            print('dest: ', dest, 'dest_info: ', dest_info)
            if listener != 'OnJoinManyStrings':
                source_info, source = ' '.join(message[from_index + 1:len(message) + 1]).split('|', 1)
            else:
                source_info = -1
                source = message[4][3:len(message[4]) - 1]
            print('source: ', source, 'source_info: ', source_info)
            last_param = ''
            if index == 0:
                last_param = "'" + str(source) + "'"
            elif (listener == 'OnNewSlicedString' or listener == 'OnNewConcatStringCopy') and index != 0:
                last_param = 'v_' + str(linenumber) + '_' + str(index)
            else:
                last_param = 'v_' + str(linenumber) + '_' + str(index - 1)
            param = 'v_' + str(linenumber) + '_' + str(index)
            js_sentence = ''
            if index == 0:
                js_sentence = param + ' = ' + last_param
            else:
                js_sentence = param + ' = ' + last_param

            if listener == 'OnJoinManyStrings':
                # print('dest: ', dest, 'Array dest: ', array_dest)
                if array_flag == 0:
                    array_flag = 1
                    # array_dest = copy.deepcopy(dest)
                    array_dest = dest
                    # print('dest2: ', dest, 'Array dest2: ', array_dest)
                    array_source.append(source)
                elif array_flag == 1 and dest == array_dest:
                    array_source.append(source)
                array_param = param

            else:
                if array_flag == 1:
                    js_sentence_array = array_param + ' = ['
                    for each in array_source:
                        js_sentence_array = js_sentence_array + "'" + each + "'" + ", "

                    js_sentence_array = js_sentence_array[0:len(js_sentence_array) - 2]
                    js_sentence_array = js_sentence_array + ']'
                    js_sentence_array = js_sentence_array + '.' + "join('')"
                    # initial
                    array_flag = 0
                    array_source = []
                    array_dest = ''
                    print('OnJoinManyStrings js sentence: ', js_sentence_array)
                    with open("js_transform.txt", 'a+') as f:
                        f.write(js_sentence_array + '\n')

                if listener == 'OnNewSubStringCopy':
                    start = source.find(dest)
                    if start != -1:
                        length = len(dest)
                        js_sentence = js_sentence + '.' + 'substring(' + str(start) + ', ' + str(start + length) + ')'
                        print('OnNewSubStringCopy js sentence: ', js_sentence)

                elif listener == 'OnNewSlicedString':
                    # only deal with simple string situation, list may be added later
                    start = source.find(dest)
                    if start != -1:
                        length = len(dest)
                        js_sentence = js_sentence + '.' + 'slice(' + str(start) + ', ' + str(start + length) + ')'
                        print('OnNewSlicedString js sentence: ', js_sentence)

                elif listener == 'OnNewConcatStringCopy':
                    start = dest.find(source)
                    if start != -1:
                        concat_msg = ''
                        # source = header
                        if start == 0:
                            concat_msg = dest[len(source):]
                            js_sentence = js_sentence + '.' + 'concat(' + "'" + str(concat_msg) + "'" + ')'
                        # source = tail
                        else:
                            concat_msg = last_param
                            js_sentence = param + ' = ' + "'" + dest[0:start] + "'" + '.concat(' + str(concat_msg) + ')'
                        print('OnNewConcatStringCopy js sentence: ', js_sentence)

                elif listener == 'NewConsString':
                    start = dest.find(source)
                    print('Start: ', start)
                    if start != -1:
                        concat_msg = ''
                        # source = header
                        if start == 0:
                            concat_msg = dest[len(source):]
                            js_sentence = js_sentence + '.' + 'concat(' + "'" + str(concat_msg) + "'" + ')'
                        # source = tail
                        else:
                            concat_msg = last_param
                            js_sentence = param + ' = ' + "'" + dest[0:start] + "'" + '.concat(' + str(concat_msg) + ')'
                        print('NewConsString js sentence: ', js_sentence)

                elif listener == 'OnNewFromJsonString':
                    pass

                elif listener == 'OnNewReplaceRegexpWithString':
                    if len(dest) == len(source):
                        diff_word = ''
                        diff_word_replace = ''
                        for i in range(len(dest)):
                            if dest[i] != source[i]:
                                diff_word = dest[i]
                                diff_word_replace = source[i]
                                break
                        pattern = '/'
                        change_to = ''
                        if diff_word_replace in special_word:
                            pattern = pattern + '\\'
                        pattern = pattern + diff_word_replace + '/g'
                        if diff_word in special_word:
                            change_to = change_to + '\\'
                        change_to = change_to + diff_word
                        js_sentence = js_sentence + '.' + 'replace(' + pattern + ', ' + "'" + change_to + "'" + ')'
                        print('OnNewReplaceRegexpWithString js sentence: ', js_sentence)

                elif listener == 'ConvertCase':
                    if dest.islower():
                        js_sentence = js_sentence + '.' + 'toLowerCase()'
                        print('ConvertCase Lower: ', js_sentence)
                    elif dest.isupper():
                        js_sentence = js_sentence + '.' + 'toUpperCase()'
                        print('ConvertCase Upper: ', js_sentence)

            # if listener != 'OnJoinManyStrings':
            # need generate js function
            js_sentence = js_sentence + ';'
            if js_sentence != '':
                with open("js_transform.txt", 'a+') as f:
                    f.write(js_sentence + '\n')
        # sink function
        else:
            with open("js_transform.txt", 'a+') as f:
                f.write('//Sink function: ' + str(info) + '\n')

    with open("js_transform.txt", 'a+') as f:
        f.write('# ' + str(trans_number))
        f.write('\n')
        trans_number = trans_number + 1


def Readdata():
    f = open("filiter_result.txt")
    lines = f.readlines()
    data = []
    for (index, line) in enumerate(lines):
        if 'total number of flows' not in line:
            start_index = line.index(':', 1)
            line = line[start_index + 1:]
            print('line:', line)
            line = eval(line)
            data.append(line)
    return data

if __name__ == '__main__':
    '''
    f = open("result.txt", 'r')
    lines = f.readlines()
    for (index, line) in enumerate(lines):
        line = line.strip('\n')
        line = line.strip('\t')
        print('Line: ', line)
        transflow(index, line)
    '''
    try:
        cmd = 'rm js_transform.txt'
        subprocess.run(cmd.split(' '), check=True)
    except Exception as e:
        pass
	
    #data = filter.ReadFile()
    #data = filter.GetFlow(data)
    data = Readdata()
    for (index, line) in enumerate(data):
        # print('Each flow data: ', line)
        try:
            if len(line) > 1:
                transflow(index, line)
        except:
            print('Error: ', line)
            break

    filter.save2file(data)
    print("Transform finished!")
