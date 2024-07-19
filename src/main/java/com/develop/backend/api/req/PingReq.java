package com.develop.backend.api.req;

import com.develop.backend.fw.master.CMMaster;

import lombok.Getter;

@Getter
public class PingReq extends CMMaster {

    private String input1;
    private String input2;

}
