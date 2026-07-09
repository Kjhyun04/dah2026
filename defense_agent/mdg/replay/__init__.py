"""replay — node-I/O JSONL 기록(record.py) + 오프라인 재생(play.py).

recorder(PA-7/PS-3)는 각 LangGraph node 업데이트(stream_mode='updates')를 시크릿 없는,
바이트 단위로 동일한 JSONL 라인으로 캡처한다. player(H-J)는 tick 타임라인을 오프라인으로
재구성하므로(테스트베드 없음, stdlib) 리뷰어가 ``run.jsonl`` 만으로 Viewer/Verifier를
구동할 수 있다. 이 패키지는 core-side다(기록 파이프라인); graph 바깥의 Verifier는 이
JSONL을 소비하며 이 패키지나 core를 결코 import하지 않는다.
"""
